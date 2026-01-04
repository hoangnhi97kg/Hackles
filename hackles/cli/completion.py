"""Shell completion for hackles CLI"""

import argparse


def setup_completion(parser: argparse.ArgumentParser) -> None:
    """Enable shell completion for the parser.

    This uses argcomplete which supports bash, zsh, tcsh, and fish.

    Installation for bash:
        eval "$(register-python-argcomplete hackles)"

    Installation for zsh:
        autoload -U bashcompinit && bashcompinit
        eval "$(register-python-argcomplete hackles)"

    Installation for fish:
        register-python-argcomplete --shell fish hackles > ~/.config/fish/completions/hackles.fish

    Args:
        parser: The ArgumentParser to enable completion for
    """
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        # argcomplete not installed, skip completion setup
        pass
