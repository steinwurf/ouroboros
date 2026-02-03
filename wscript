#! /usr/bin/env python
# encoding: utf-8

import os
import hashlib
import platform
import shlex

from waflib.Build import BuildContext


APPNAME = "ouroboros"
VERSION = "1.1.0"


def options(ctx):
    ctx.load("cmake")

    if ctx.is_toplevel():
        # Add option for filtering the python tests
        ctx.add_option(
            "--python-test-filter",
            action="store",
            default="",
            help="Filter the python tests to run",
        )

        # Add option for filtering the go tests
        ctx.add_option(
            "--go-test-filter",
            action="store",
            default="",
            help="Filter the go tests to run (passed to -run)",
        )


def configure(ctx):
    ctx.load("cmake")
    if ctx.is_toplevel():

        # Run cmake configuration
        ctx.cmake_configure()


def build(ctx):
    ctx.load("cmake")
    if ctx.is_toplevel():
        ctx.cmake_build()


def prepare_release(ctx):
    """Prepare a release."""

    # Rewrite versions
    with ctx.rewrite_file(filename="src/ouroboros/version.hpp") as f:
        pattern = r"#define STEINWURF_OUROBOROS_VERSION v\d+_\d+_\d+"
        replacement = "#define STEINWURF_OUROBOROS_VERSION v{}".format(
            VERSION.replace(".", "_")
        )
        f.regex_replace(pattern=pattern, replacement=replacement)

    with ctx.rewrite_file(filename="CMakeLists.txt") as f:
        pattern = r"project\(ouroboros VERSION \d+\.\d+\.\d+\)"
        replacement = "project(ouroboros VERSION {})".format(VERSION)

        f.regex_replace(pattern=pattern, replacement=replacement)

    with ctx.rewrite_file(filename="python/pyproject.toml") as f:
        pattern = r'version = "\d+\.\d+\.\d+"'
        replacement = 'version = "{}"'.format(VERSION)
        f.regex_replace(pattern=pattern, replacement=replacement)

    go_version_file = "go/ouroboros/version.go"
    if os.path.exists(go_version_file):
        with ctx.rewrite_file(filename=go_version_file) as f:
            pattern = r'PackageVersion = "\d+\.\d+\.\d+"'
            replacement = 'PackageVersion = "{}"'.format(VERSION)
            f.regex_replace(pattern=pattern, replacement=replacement)


def _get_shm_generator_path(ctx):
    """Return the path to ouroboros_shm_generator. Fatal if not found."""
    binary_name = "ouroboros_shm_generator"

    if platform.system() == "Linux":
        shm_generator = os.path.join(ctx.env.CMAKE_BUILD_DIR, "bin", binary_name)
    elif platform.system() == "Windows":
        shm_generator = os.path.join(
            ctx.env.CMAKE_BUILD_DIR,
            "bin",
            ctx.env.CMAKE_BUILD_TYPE,
            binary_name + ".exe",
        )
    elif platform.system() == "Darwin":
        shm_generator = os.path.join(
            ctx.env.CMAKE_BUILD_DIR,
            "bin",
            binary_name,
        )
    else:
        ctx.fatal("Unsupported platform: {}".format(platform.system()))

    if not os.path.exists(shm_generator):
        ctx.fatal(
            "Cannot find ouroboros_shm_generator binary in {}, did you run "
            "'waf build'?".format(shm_generator)
        )

    return shm_generator


class PythonTestContext(BuildContext):
    cmd = "python_test"
    fun = "python_test"


def python_test(ctx):
    shm_generator = _get_shm_generator_path(ctx)

    root = ctx.path.abspath()
    pyproject = os.path.join(root, "python", "pyproject.toml")
    if not os.path.isfile(pyproject):
        ctx.fatal("python/pyproject.toml not found")

    with open(pyproject, "r") as f:
        pyproject_sha1 = hashlib.sha1(f.read().encode("utf-8")).hexdigest()[:8]

    name = "venv-python-{}".format(pyproject_sha1)
    exists = os.path.isdir(name)

    venv = ctx.create_virtualenv(name=name, overwrite=False)

    if not exists:
        venv.env["PIP_IGNORE_INSTALLED"] = ""
        python_dir = os.path.join(root, "python")
        # Upgrade pip/setuptools so editable install from pyproject.toml works
        # (PEP 660); macOS CLI tools and other environments often ship old pip.
        venv.run("python -m pip install --upgrade pip setuptools wheel")
        venv.run('python -m pip install -e "{}[test]"'.format(python_dir))

    # Pass generator path via pytest option (works on Windows; VAR=value is Unix-only)
    def _shell_quote(s):
        if platform.system() == "Windows":
            return '"' + s.replace('"', '\\"') + '"' if (" " in s or '"' in s) else s
        return shlex.quote(s)

    gen_opt = _shell_quote(shm_generator)
    cmd_parts = ["pytest", "python/tests", "--ouroboros-shm-generator=" + gen_opt]
    if ctx.options.python_test_filter:
        cmd_parts.append("-k")
        cmd_parts.append(_shell_quote(ctx.options.python_test_filter))
    venv.run(" ".join(cmd_parts))


class GoTestContext(BuildContext):
    cmd = "go_test"
    fun = "go_test"


def go_test(ctx):
    shm_generator = _get_shm_generator_path(ctx)

    root = ctx.path.abspath()
    go_dir = os.path.join(root, "go")

    env = os.environ.copy()
    env["OUROBOROS_SHM_GENERATOR"] = shm_generator

    cmd_parts = ["go", "test", "./...", "-v"]
    if ctx.options.go_test_filter:
        cmd_parts.extend(["-run", ctx.options.go_test_filter])

    ctx.exec_command(
        cmd_parts,
        cwd=go_dir,
        env=env,
    )
