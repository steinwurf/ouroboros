#! /usr/bin/env python
# encoding: utf-8


APPNAME = "ouroboros"
VERSION = "0.0.0"


def options(ctx):
    ctx.load("cmake")

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

