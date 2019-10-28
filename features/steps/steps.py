import datetime
import shlex

from behave import given, then, when
from hamcrest import assert_that, equal_to

from features.util import launch_trusty_lxd_container, lxc_exec


CONTAINER_PREFIX = "behave-test-"


@given("a trusty lxd container")
def given_a_trusty_lxd_container(context):
    now = datetime.datetime.now()
    context.container_name = CONTAINER_PREFIX + now.strftime("%s%f")
    launch_trusty_lxd_container(context, context.container_name)


@given("ubuntu-advantage-tools is installed")
def given_uat_is_installed(context):
    lxc_exec(
        context.container_name,
        [
            "add-apt-repository",
            "--yes",
            "ppa:canonical-server/ua-client-daily",
        ],
    )
    lxc_exec(context.container_name, ["apt-get", "update", "-qq"])
    lxc_exec(
        context.container_name,
        ["apt-get", "install", "-qq", "-y", "ubuntu-advantage-tools"],
    )


@when("I run `{command}` {user_spec}")
def when_i_run_command(context, command, user_spec):
    prefix = []
    if user_spec == "with sudo":
        prefix = ["sudo"]
    elif user_spec != "as non-root":
        raise Exception(
            "The two acceptable values for user_spec are: 'with sudo',"
            " 'as non-root'"
        )
    process = lxc_exec(
        context.container_name,
        prefix + shlex.split(command),
        capture_output=True,
        text=True,
    )
    context.process = process


@then("I will see the following on stdout")
def then_i_will_see_on_stdout(context):
    assert_that(context.process.stdout.strip(), equal_to(context.text))


@then("I will see the following on stderr")
def then_i_will_see_on_stderr(context):
    assert_that(context.process.stderr.strip(), equal_to(context.text))
