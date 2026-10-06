"""Command line interface of the Wadjet agent."""

import typer

app = typer.Typer(
    help="Run Wadjet scanners and upload findings to a Wadjet server.", no_args_is_help=True
)


@app.callback()
def root() -> None:
    """Wadjet analysis agent."""


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()
