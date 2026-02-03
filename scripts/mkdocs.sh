#!/bin/sh
########################################################################
# Use markdown_helper gem to generate docs. It's much nicer than using 
# vscode's broken TOC generator plugin.
# muquit@muquit.com Dec-22-2018 
# use markdown-helper v2.1.0 - Dec-22-2018. TOC generation is much simpler
# Udpate: use my markdown-toc-go Feb-02-2026 
########################################################################
CAT="/bin/cat"

LF="./docs/21-license.md"
${RM} $TF

gen_license_file()
{
    echo "# License is MIT" > $LF
    echo "" >> $LF
    echo '```' >> $LF
    ${CAT} ./LICENSE.txt >>$LF
    echo "" >> $LF
    echo '```' >> $LF
}

run_markdown_toc() {
    local -r prog='markdown-toc-go'
    local -r gfile='./docs/glossary.txt'
    local -r m='./docs/main.md'
    local -r r='./README.md'
    ${prog} \
        -i ${m} -o ${r} \
        --glossary ${gfile} \
        -f
    ${prog} \
    -i docs/ChangeLog.md \
    -o ./ChangeLog.md \
    --glossary docs/glossary.txt \
    -f -no-credit
}
#-----------------------------------------

gen_license_file
run_markdown_toc
