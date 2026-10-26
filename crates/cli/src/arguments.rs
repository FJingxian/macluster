use std::{collections::BTreeMap, path::PathBuf};

use macluster_protocol::identifiers::{Id128, NodeId, QueueName, RequestId};
use thiserror::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubmitOptions {
    pub interactive: bool,
    pub verbose: bool,
    pub queue: Option<QueueName>,
    pub node: Option<NodeId>,
    pub name: Option<String>,
    pub walltime_secs: Option<u64>,
    pub cwd: Option<PathBuf>,
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub script: Option<PathBuf>,
    pub wrap: Option<String>,
    pub request_id: Option<RequestId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CliError {
    #[error("missing value for {0}")]
    MissingValue(String),
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("unsupported resource request flag: {0}; this release schedules whole nodes")]
    UnsupportedResourceFlag(String),
    #[error("environment variable cannot override a reserved name: {0}")]
    ReservedEnvironment(String),
    #[error("environment assignment must be KEY=VALUE with a valid key")]
    InvalidEnvironment,
    #[error("--wrap cannot be combined with a script path")]
    ConflictingInputs,
    #[error("submit requires exactly one script path or --wrap command")]
    MissingInput,
    #[error("submit accepts exactly one script path")]
    MultipleInputs,
    #[error("unknown submit option: {0}")]
    UnknownOption(String),
    #[error("invalid shell-style declaration near: {0}")]
    InvalidDeclaration(String),
}

pub fn parse_submit_args<I, S>(args: I) -> Result<SubmitOptions, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_options(
        args.into_iter()
            .map(|arg| arg.as_ref().to_owned())
            .collect(),
        false,
    )
}

pub fn parse_script_declarations(script: &str) -> Result<SubmitOptions, CliError> {
    let mut options = Vec::new();
    for line in script.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            if let Some(declaration) = rest.strip_prefix("MSUB")
                && declaration.chars().next().is_none_or(char::is_whitespace)
            {
                options.extend(tokenize_declaration(declaration.trim())?);
            }
            continue;
        }
        break;
    }
    let parsed = parse_options(options, true)?;
    if parsed.script.is_some() || parsed.wrap.is_some() || parsed.request_id.is_some() {
        return Err(CliError::InvalidDeclaration(
            "unsupported declaration".to_owned(),
        ));
    }
    Ok(parsed)
}

pub fn merge_submit_options(declarations: SubmitOptions, cli: SubmitOptions) -> SubmitOptions {
    let mut env = declarations.env;
    env.extend(cli.env);
    SubmitOptions {
        interactive: cli.interactive,
        verbose: declarations.verbose || cli.verbose,
        queue: cli.queue.or(declarations.queue),
        node: cli.node.or(declarations.node),
        name: cli.name.or(declarations.name),
        walltime_secs: cli.walltime_secs.or(declarations.walltime_secs),
        cwd: cli.cwd.or(declarations.cwd),
        stdout_path: cli.stdout_path.or(declarations.stdout_path),
        stderr_path: cli.stderr_path.or(declarations.stderr_path),
        env,
        script: cli.script,
        wrap: cli.wrap,
        request_id: cli.request_id,
    }
}

fn parse_options(args: Vec<String>, declarations_only: bool) -> Result<SubmitOptions, CliError> {
    let mut options = SubmitOptions::default();
    let mut positionals = Vec::new();
    let mut index = 0;
    let mut positional_only = false;
    while index < args.len() {
        let argument = &args[index];
        if positional_only {
            positionals.push(argument.clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            positional_only = true;
            index += 1;
            continue;
        }
        if matches!(
            argument.as_str(),
            "-n" | "--cores" | "-c" | "--ntasks" | "-m" | "--mem" | "--memory"
        ) {
            return Err(CliError::UnsupportedResourceFlag(argument.clone()));
        }
        let takes_value = |option: &str, i: &mut usize| -> Result<String, CliError> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| CliError::MissingValue(option.to_owned()))
        };
        match argument.as_str() {
            "-Is" if !declarations_only => options.interactive = true,
            "-v" | "--verbose" => options.verbose = true,
            "-q" | "--queue" => {
                let raw = takes_value(argument, &mut index)?;
                options.queue =
                    Some(QueueName::new(raw.clone()).map_err(|_| CliError::InvalidValue(raw))?);
            }
            "--node" => {
                let raw = takes_value(argument, &mut index)?;
                options.node =
                    Some(NodeId::new(raw.clone()).map_err(|_| CliError::InvalidValue(raw))?);
            }
            "-J" | "--name" => {
                let name = takes_value(argument, &mut index)?;
                if name.trim().is_empty() {
                    return Err(CliError::InvalidValue("empty job name".to_owned()));
                }
                options.name = Some(name);
            }
            "-t" | "--time" => {
                let time = takes_value(argument, &mut index)?;
                options.walltime_secs = Some(parse_walltime(&time)?);
            }
            "--cwd" => options.cwd = Some(PathBuf::from(takes_value(argument, &mut index)?)),
            "-o" | "--output" => {
                options.stdout_path = Some(PathBuf::from(takes_value(argument, &mut index)?));
            }
            "-e" | "--error" => {
                options.stderr_path = Some(PathBuf::from(takes_value(argument, &mut index)?));
            }
            "--env" if !declarations_only => {
                let assignment = takes_value(argument, &mut index)?;
                let Some((key, value)) = assignment.split_once('=') else {
                    return Err(CliError::InvalidEnvironment);
                };
                if !valid_env_key(key) || value.contains('\0') {
                    return Err(CliError::InvalidEnvironment);
                }
                if key.starts_with("MCLUSTER_") {
                    return Err(CliError::ReservedEnvironment(key.to_owned()));
                }
                options.env.insert(key.to_owned(), value.to_owned());
            }
            "--request-id" if !declarations_only => {
                let raw = takes_value(argument, &mut index)?;
                options.request_id = Some(RequestId(
                    Id128::parse(&raw).map_err(|_| CliError::InvalidValue(raw))?,
                ));
            }
            "--wrap" if !declarations_only => {
                options.wrap = Some(takes_value(argument, &mut index)?);
            }
            option if option.starts_with('-') => {
                return Err(CliError::UnknownOption(option.to_owned()));
            }
            _ => {
                positionals.push(argument.clone());
                if !declarations_only {
                    positionals.extend(args[index + 1..].iter().cloned());
                    break;
                }
            }
        }
        index += 1;
    }

    if declarations_only && !positionals.is_empty() {
        return Err(CliError::InvalidDeclaration(positionals.join(" ")));
    }
    if !declarations_only {
        if options.wrap.is_some() && !positionals.is_empty() {
            return Err(CliError::ConflictingInputs);
        }
        if options.wrap.is_none()
            && positionals.is_empty()
            && options.request_id.is_none()
            && !options.interactive
        {
            return Err(CliError::MissingInput);
        }
        match positionals.as_slice() {
            [] => {}
            [script] => options.script = Some(PathBuf::from(script)),
            command => options.wrap = Some(quote_argv(command)),
        }
    }
    Ok(options)
}

pub(crate) fn quote_argv(arguments: &[String]) -> String {
    arguments
        .iter()
        .map(|argument| format!("'{}'", argument.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn tokenize_shell_words(input: &str) -> Result<Vec<String>, CliError> {
    tokenize_declaration(input)
}

fn parse_walltime(value: &str) -> Result<u64, CliError> {
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() != 3 {
        return Err(CliError::InvalidValue(value.to_owned()));
    }
    let hours = fields[0]
        .parse::<u64>()
        .map_err(|_| CliError::InvalidValue(value.to_owned()))?;
    let minutes = fields[1]
        .parse::<u64>()
        .map_err(|_| CliError::InvalidValue(value.to_owned()))?;
    let seconds = fields[2]
        .parse::<u64>()
        .map_err(|_| CliError::InvalidValue(value.to_owned()))?;
    if minutes >= 60 || seconds >= 60 {
        return Err(CliError::InvalidValue(value.to_owned()));
    }
    hours
        .checked_mul(3600)
        .and_then(|total| total.checked_add(minutes * 60 + seconds))
        .ok_or_else(|| CliError::InvalidValue(value.to_owned()))
}

fn valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn tokenize_declaration(input: &str) -> Result<Vec<String>, CliError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let mut result = Vec::new();
    let mut token = String::new();
    let mut token_started = false;
    let mut quote = Quote::None;
    let mut escaped = false;
    for character in input.chars() {
        if escaped {
            if quote == Quote::Double && !matches!(character, '"' | '\\' | '$' | '`' | '\n') {
                token.push('\\');
            }
            if character != '\n' {
                token.push(character);
                token_started = true;
            }
            escaped = false;
            continue;
        }
        match (quote, character) {
            (Quote::Single, '\'') => quote = Quote::None,
            (Quote::Double, '"') => quote = Quote::None,
            (Quote::None, '\'') => {
                quote = Quote::Single;
                token_started = true;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                token_started = true;
            }
            (Quote::Single, _) => token.push(character),
            (Quote::Double, '\\') | (Quote::None, '\\') => escaped = true,
            (Quote::None, c) if c.is_whitespace() => {
                if token_started {
                    result.push(std::mem::take(&mut token));
                    token_started = false;
                }
            }
            (_, _) => {
                token.push(character);
                token_started = true;
            }
        }
    }
    if escaped || quote != Quote::None {
        return Err(CliError::InvalidDeclaration(input.to_owned()));
    }
    if token_started {
        result.push(token);
    }
    Ok(result)
}
