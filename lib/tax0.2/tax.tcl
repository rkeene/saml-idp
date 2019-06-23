#! /usr/bin/env tclsh

namespace eval ::tax {}

# ::tax::__cleanprops -- Clean parsed XML properties
#
#	This command cleans parsed XML properties by removing the
#	trailing slash and replacing equals by spaces so as to produce
#	a list that is suitable for an array set command.
#
# Arguments:
#	props	Parsed XML properties
#
# Results:
#	Return an event list that is suitable for an array set
#
# Side Effects:
#	None.
proc ::tax::__cleanprops { props } {
    set name {([A-Za-z_:]|[^\x00-\x7F])([A-Za-z0-9_:.-]|[^\x00-\x7F])*}
    set attval {"[^"]*"|'[^']*'|\w}; # "... Makes emacs happy
    set ret [regsub -all -- "($name)\\s*=\\s*($attval)" \
		[regsub "/$" $props ""] "\\1 \\4"]
    set ret [string map [list "'" "\""] $ret]
    return $ret
}

# ::tax::parse -- Low-level 10 lines magic parser
#
#	This procedure is the core of the tiny XML parser and does its
#	job in 10 lines of "hairy" code.  The command will call the
#	command passed as an argument for each XML tag that is found
#	in the XML code passed as an argument.  Error checking is less
#	than minimum!  The command will be called with the following
#	respective arguments: name of the tag, boolean telling whether
#	it is a closing tag or not, boolean telling whether it is a
#	self-closing tag or not, list of property (array set-style)
#	and body of tag, if available.
#
# Arguments:
#	cmd	Command to call for each tag found.
#	xml	String containing the XML to be parsed.
#	start	Name of the pseudo tag marking the beginning/ending of document
#
# Results:
#	None.
#
# Side Effects:
#	None.
proc ::tax::parse {cmd xml {start docstart}} {
    # Convert CDATA sections to variable references to ensure that nothing
    # modifies them along the way
    set newxml ""
    for {set idx 0} {1} {set idx $endidx} {
        # Determine previous start index
        set previdx $idx

        # Determine where CDATA section begins
        set idx [string first {<![CDATA[} $xml $idx]
        if {$idx == -1} {
            break
        }

        # Determine where CDATA section ends
        set endidx [string first {]]>} $xml $idx]
        if {$endidx == "-1"} {
            set endidx [expr {[string length $xml] - 1}]
        }

        # Determine where the the XML ends
        set xmlendidx [expr {$idx - 1}]

        # Determine where the CDATA body begins
        set idx [expr {$idx + 9}]

        # Determine where the CDATA body ends
        set endidx [expr {$endidx - 1}]

        # Select the CDATA body from the XML
        set data [string range $xml $idx $endidx]

        # Adjust the end index to include the end of the tag since it will be
        # used for exclusion later
        set endidx [expr {$endidx + 4}]

        # Store data associated with this start index
        set key "@!@CDATA-${idx}@!@"
        set cdata($key) $data

        # Remove the whole CDATA tag+body from the XML
        append newxml [string range $xml $previdx $xmlendidx]
        append newxml $key
    }

    # Append the trailing data (if any)
    append newxml [string range $xml $previdx end]

    # Put the redacted data back into place
    set xml $newxml
    unset newxml

    # Replace open and close braces with XML entities to prevent them from
    # interfering with command formation
    regsub -all \{ $xml {\&ob;} xml
    regsub -all \} $xml {\&cb;} xml
    regsub -all {\\} $xml {\\\\}

    # Create regular expresion that matches tags and replaces them with valid
    # Tcl commands
    set exp {<(/?)([^\s/>]+)\s*([^>]*)>}
    set sub "\}\n$cmd {\\2} \[expr \{{\\1} ne \"\"\}\] \[regexp \{/$\} {\\3}\] \
             \[::tax::__cleanprops \{\\3\}\] \{"
    regsub -all $exp $xml $sub xml

    # Re-introduce CDATA sections into XML, which has been converted to a set
    # of Tcl commands.  This will fail if the CDATA contains unbalanced curly
    # braces.
    set xml [string map [array get cdata] $xml]

    # Evaluate generated commands
    eval "$cmd {$start} 0 0 {} \{$xml\}"

    # Evaluate the document start close tag
    eval "$cmd {$start} 1 0 {} {}"
}

package provide tax 0.2
