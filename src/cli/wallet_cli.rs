// src/cli/wallet_cli.rs — complete fixed CLI loop with Box::leak for owner_api

use crate::cmd::wallet_args;
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use api_common::types::Token;
use api_common::OwnerRpc;
use clap::App;
use clap::ArgMatches;
use lurker_keychain as keychain;
use lurker_wallet_config::WalletConfig;
use lurker_wallet_controller::command;
use lurker_wallet_controller::command::GlobalArgs;
use lurker_wallet_impls::DefaultLCProvider;
use lurker_wallet_impls::Error;
use lurker_wallet_impls::Owner;
use lurker_wallet_impls::{DefaultWalletImpl, HTTPNodeClient};
use lurker_wallet_libwallet::WalletOutputBatch;
use lurker_wallet_libwallet::{NodeClient, WalletInst, WalletLCProvider};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, EditMode, Editor, Helper, OutputStreamType};
use std::borrow::Cow::{self, Borrowed, Owned};
use std::sync::Arc;

const COLORED_PROMPT: &'static str = "\x1b[36mlurker-wallet>\x1b[0m ";
const PROMPT: &'static str = "lurker-wallet> ";

// static for keeping track of current stdin buffer contents
lazy_static! {
	static ref STDIN_CONTENTS: Mutex<String> = Mutex::new(String::from(""));
}

#[macro_export]
macro_rules! cli_message_inline {
    ($fmt_string:expr, $( $arg:expr ),+) => {
        {
            use std::io::Write;
            let contents = STDIN_CONTENTS.lock();
            print!("\r");
            print!($fmt_string, $( $arg ),*);
            print!(" {}", COLORED_PROMPT);
            print!("\x1B[J");
            print!("{}", *contents);
            std::io::stdout().flush().unwrap();
        }
    };
}

#[macro_export]
macro_rules! cli_message {
    ($fmt_string:expr, $( $arg:expr ),+) => {
        {
            use std::io::Write;
            print!($fmt_string, $( $arg ),*);
            println!();
            std::io::stdout().flush().unwrap();
        }
    };
}

/// Function to check if the command requires a keychain mask (i.e., write/signing operation)
fn requires_mask(args: &ArgMatches) -> bool {
	matches!(
		args.subcommand().0,
		"send" | "pay" | "invoice" | "finalize" | "repost" | "cancel" | "export_proof"
	)
}

// src/cli/wallet_cli.rs — final fix for CLI loop with per-command leak

pub fn command_loop<C>(
	wallet_inst: Arc<
		Mutex<
			Box<
				dyn WalletInst<'static, DefaultLCProvider<'static, C>, C, keychain::ExtKeychain>
					+ 'static,
			>,
		>,
	>,
	mut keychain_mask: Option<SecretKey>,
	wallet_config: &WalletConfig,
	global_wallet_args: &command::GlobalArgs,
	test_mode: bool,
) -> Result<(), Error>
where
	C: NodeClient + 'static,
{
	let editor = Config::builder()
		.history_ignore_space(true)
		.completion_type(CompletionType::List)
		.edit_mode(EditMode::Emacs)
		.output_stream(OutputStreamType::Stdout)
		.build();

	let mut reader = Editor::with_config(editor);
	reader.set_helper(Some(EditorHelper(
		FilenameCompleter::new(),
		MatchingBracketHighlighter::new(),
	)));

	let yml = load_yaml!("../bin/lurker-wallet.yml");
	let mut app = App::from_yaml(yml).version(crate_version!());

	let mut wallet_opened = false;

	loop {
		match reader.readline(PROMPT) {
			Ok(command) => {
				if command.is_empty() {
					continue;
				}
				if command.to_lowercase() == "exit" {
					break;
				}

				// reset buffer
				{
					let mut contents = STDIN_CONTENTS.lock();
					*contents = String::from("");
				}

				// Augment command for clap parsing
				let augmented_command = format!("lurker-wallet {}", command);
				let args = match app
					.get_matches_from_safe_borrow(augmented_command.trim().split_whitespace())
				{
					Ok(a) => a,
					Err(e) => {
						cli_message!("{}", e);
						continue;
					}
				};

				// Prompt for password/mask if command requires signing and mask is None
				if requires_mask(&args) && keychain_mask.is_none() {
					let wallet_lock = wallet_inst.lock();
					let mut lc = wallet_lock.lc_provider().unwrap();
					keychain_mask = match lc.open_wallet(
						None,
						wallet_args::prompt_password(&global_wallet_args.password),
						false,
						false,
					) {
						Ok(m) => m,
						Err(e) => {
							cli_message!("{}", e);
							continue;
						}
					};
				}

				// Handle open/close separately
				keychain_mask = match args.subcommand() {
					("open", Some(_)) => {
						let wallet_lock = wallet_inst.lock();
						let mut lc = wallet_lock.lc_provider().unwrap();
						let mask = match lc.open_wallet(
							None,
							wallet_args::prompt_password(&global_wallet_args.password),
							false,
							false,
						) {
							Ok(m) => {
								wallet_opened = true;
								m
							}
							Err(e) => {
								cli_message!("{}", e);
								None
							}
						};
						if let Some(account) = args.value_of("account") {
							if wallet_opened {
								let wallet_inst_inner = lc.wallet_inst()?;
								wallet_inst_inner.set_parent_key_id_by_name(account)?;
							}
						}
						mask
					}
					("close", Some(_)) => {
						let wallet_lock = wallet_inst.lock();
						let mut lc = wallet_lock.lc_provider().unwrap();
						lc.close_wallet(None)?;
						None
					}
					_ => keychain_mask,
				};

				// Leak a new Owner for this command to avoid borrow overlap in loop
				let owner_api_box =
					Box::new(Owner::new(wallet_inst.clone(), keychain_mask.clone()));
				let owner_api: &'static mut Owner<
					'static,
					DefaultLCProvider<'static, C>,
					C,
					keychain::ExtKeychain,
				> = Box::leak(owner_api_box);

				match wallet_args::parse_and_execute(
					owner_api,
					keychain_mask.clone(),
					wallet_config,
					global_wallet_args,
					&args,
					test_mode,
					true,
					wallet_inst.clone(),
				) {
					Ok(_) => {
						cli_message!("Command '{}' completed", args.subcommand().0);
					}
					Err(err) => {
						cli_message!("{}", err);
					}
				}
			}
			Err(ReadlineError::Interrupted) => {
				println!("^C");
				continue;
			}
			Err(ReadlineError::Eof) => {
				println!("^D");
				break;
			}
			Err(err) => {
				cli_message!("Error reading line: {}", err);
				break;
			}
		}
	}

	Ok(())
}

struct EditorHelper(FilenameCompleter, MatchingBracketHighlighter);

impl Completer for EditorHelper {
	type Candidate = Pair;

	fn complete(
		&self,
		line: &str,
		pos: usize,
		ctx: &Context<'_>,
	) -> std::result::Result<(usize, Vec<Pair>), ReadlineError> {
		self.0.complete(line, pos, ctx)
	}
}

impl Hinter for EditorHelper {
	fn hint(&self, line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
		let mut contents = STDIN_CONTENTS.lock();
		*contents = line.into();
		None
	}
}

impl Highlighter for EditorHelper {
	fn highlight<'l>(&self, line: &'l str, pos: usize) -> Cow<'l, str> {
		self.1.highlight(line, pos)
	}

	fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
		&'s self,
		prompt: &'p str,
		default: bool,
	) -> Cow<'b, str> {
		if default {
			Borrowed(COLORED_PROMPT)
		} else {
			Borrowed(prompt)
		}
	}

	fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
		Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
	}

	fn highlight_char(&self, line: &str, pos: usize) -> bool {
		self.1.highlight_char(line, pos)
	}
}

impl Validator for EditorHelper {}
impl Helper for EditorHelper {}
