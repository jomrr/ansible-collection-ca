"""Generated Sphinx configuration."""

from sphinx.application import Sphinx


def setup(app: Sphinx) -> None:
    """Configure the docsite through Sphinx's application setup hook."""
    app.setup_extension("sphinx.ext.intersphinx")
    app.setup_extension("sphinx_antsibull_ext")
    app.config.project = "jomrr.ca"
    app.config.html_theme = "sphinx_ansible_theme"
    app.config.intersphinx_mapping = {
        "ansible": ("https://docs.ansible.com/projects/ansible/latest/", None),
    }
