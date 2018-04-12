import sys
import click
import dnsaudit


class Context(object):
    def __init__(self):
        self.verbose = False
        # self.home = os.getcwd()

    def log(self, msg, *args):
        """Logs a message to stderr"""
        if args:
            msg %= args
        click.echo(msg, file=sys.stderr)

    def vlog(self, msg, *args):
        """Logs a message to stderr only if verbose is enabled."""
        if self.verbose:
            self.log(msg, *args)


pass_context = click.make_pass_decorator(Context, ensure=True)


@click.group()
@click.version_option()
@click.argument('database', type=str)
@click.option('-c', '--config', type=click.File('r'),
              help="Config file")
@click.option('-t', '--threads', type=int,
              help='Amount of concurrent threads for audit tasks.')
@pass_context
def cli(context, database, config, threads):
    """Perform a DNS audit on a set of hostnames, with a set of rules for the
    queries. Each time an audit is performed, the results are appended to the
    database.

    Add/remove domains to the lookup table with add/rem/import commands.

    Change the record types and subdomains looked up with the rules commands.

    Generate reports and output with history/diff/report commands.

    For help with each command, add --help after it.

    Arguments: <database>  The persistent storage for all data."""
    click.echo("Initialize.")
    context.database = database
    context.config = config
    context.threads = threads
    pass


@cli.command('add')
@click.argument('hostname', type=str)
@pass_context
def add_host(context, hostname):
    """Adds a single hostname to the lookup table."""
    click.echo(context)
    click.echo(hostname)


@cli.command('rem')
@click.argument('hostname', type=str)
@pass_context
def rem_host(context, hostname):
    """Removes a single hostname from the lookup table."""
    click.echo(context)
    click.echo(hostname)


@cli.command('list')
@pass_context
def get_hosts(context):
    """Prints all of the hostnames in the lookup table."""
    click.echo(context)
    click.echo("list hosts")


@cli.command('lookup')
@pass_context
@click.argument('hostname', type=str)
def lookup_host(context, hostname):
    """
    Performs a full lookup on a single host.
    Prints the result to STDOUT and also logs it.
    :param hostname:
    :return:
    """
    click.echo(context)
    click.echo(hostname)


@cli.command('history')
@click.argument('hostname', type=str)
@pass_context
def hostame_history(context, hostname):
    """
    Prints the entire lookup history for <hostname>
    :param hostname:
    :return:
    """
    click.echo(context)
    click.echo(hostname)


@cli.command('import')
@click.argument('host_list', type=click.File('r'))
@pass_context
def import_hosts(context, host_list):
    """
    Imports a list of hosts into the lookup table.
    :param host_list:
    :return:
    """
    click.echo(context)
    for line in host_list:
        click.echo('hostname: %s' % line.strip())


@cli.command('diff')
@click.option('-d', '--depth', type=int,
              help='How many lookups into the past to check. '
                   'Use 0 for everything. Default: 1')
@pass_context
def get_diffs(context, depth):
    """
    Shows all of the changes between the last run, and the one before it.
    :return:
    """
    click.echo(context)
    click.echo('depth: %s' % depth)


@cli.command('start')
@click.option('-q', '--quiet', is_flag=True,
              help='Suppress all output.')
@click.option('-v', '--verbose', is_flag=True,
              help='Verbose output.')
@click.option('-l', '--light', is_flag=True,
              help='Perform light logging. Does not make an entry if the '
                   'result has not changed since last run. This can save some '
                   'disk space on huge data sets.')
@pass_context
def start_audit(context, light, quiet, verbose):
    """
    Starts an audit on all hosts in the lookup table, using the configurations
    currently saved.
    """
    click.echo(context)
    click.echo('light: %s' % light)
    click.echo('quiet: %s' % quiet)
    click.echo('verbose: %s' % verbose)


@cli.command('report')
@click.argument('output', type=click.File('w'), default='-')
@click.option('-a', '--all', is_flag=True,
              help='Print all lookup results, not just the most recent.')
@click.option('format', '-c', '--csv', is_flag=True, flag_value='csv',
              help="Print results in .csv format.")
@click.option('format', '-z', '--zonefile', is_flag=True, flag_value='zone',
              help='Print results in a zonefile-ish format. (ignores -a)')
@pass_context
def get_report(context, output, format, all):
    """Prints a complete report of DNS lookups to <output> (default STDOUT)"""
    click.echo(context)
    click.echo('output: %s' % output)
    click.echo('format: %s' % format)
    click.echo('all: %s' % all)


@cli.group('rules')
@pass_context
def rules(context):
    """
    Manage lookup rules.
    :return:
    """
    click.echo(context)


@rules.command('list')
@pass_context
def list_rules(context):
    """List all current lookup rules."""
    click.echo(context)


@rules.command('add')
@click.argument('type', type=str)
@click.argument('subdomain', type=str, default='')
@pass_context
def add_rule(context, type, subdomain):
    """Adds a new lookup rule to the ruleset. <type> [subdomain]"""
    click.echo(context)
    click.echo('type: %s' % type)
    click.echo('subdomain: %s' % subdomain)


@rules.command('rem')
@click.argument('type', type=str)
@click.argument('subdomain', type=str, default='')
@pass_context
def rem_rule(context, type, subdomain):
    """Removes a specific lookup rule from the ruleset. <type> [subdomain]"""
    click.echo(context)
    click.echo('type: %s' % type)
    click.echo('subdomain: %s' % subdomain)


@rules.command('set')
@click.argument('ruleset_file', type=click.File('r'))
@pass_context
def set_rules(context, ruleset_file):
    """
    Sets the ruleset to exactly the ruleset contained in <ruleset_file>

    Input can be file or '-' for STDIN
    """
    click.echo(context)
    for line in ruleset_file:
        click.echo('ruleadd: %s' % line.strip())


@rules.command('import')
@click.argument('ruleset_file', type=click.File('r'))
@pass_context
def import_rules(context, ruleset_file):
    """
    Imports the ruleset contained in <ruleset_file> into the current ruleset.

    Input can be file or '-' for STDIN
    """
    click.echo(context)
    for line in ruleset_file:
        click.echo('ruleadd: %s' % line.strip())


@rules.command('reset')
@pass_context
def reset_rules(context):
    """
    Resets the ruleset to default state.
    """
    click.echo(context)


if __name__ == '__main__':
    cli()   
