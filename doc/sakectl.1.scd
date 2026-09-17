sakectl(1)

# NAME

sakectl - Manage a running instance of the sake IRC bouncer

# SYNOPSIS

*sakectl* [options...] <command...>

# DESCRIPTION

sakectl sends a _BouncerServ_ command to a running sake instance. See the
_IRC SERVICE_ section in *sake*(1) for more information.

sakectl requires a _listen unix+admin://_ directive in the sake configuration
file. sakectl needs to be run with write permissions on the sake admin socket.

# OPTIONS

*-h, -help*
	Show help message and quit.

*-config* <path>
	Path to the config file. If unset, the default config file path is used,
	if any.

# AUTHORS

sake is a fork of soju maintained by TehPeGaSuS. soju itself is maintained by
Simon Ser <contact@emersion.fr> and other open-source contributors; for more
information about upstream soju, see <https://soju.im>. For sake-specific
changes and issues, see <https://github.com/TehPeGaSuS/sake>.

# SEE ALSO

*sake*(1)
