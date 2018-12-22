#!/bin/sh
########################################################################
# Use markdown_helper gem to generate docs. It's much nicer than using 
# vscode's broken TOC generator plugin.
# muquit@muquit.com Dec-22-2018 
########################################################################
MH="markdown_helper"
RM="/bin/rm -f"
DOC_DIR="./docs"
CAT="/bin/cat"

pushd $DOC_DIR

TF="main.txt"
LF="21-license.md"
${RM} $TF

gen_license_file()
{
    echo "# License is MIT" > $LF
    echo "" >> $LF
    echo '```' >> $LF
    ${CAT} ../LICENSE.txt >>$LF
    echo "" >> $LF
    echo '```' >> $LF
}

write_md_line()
{
    FILE=$1
    echo "@[:markdown]($FILE)" >> ${TF}
    echo "" >> ${TF}
}

write_footer()
{
    echo "---" >> ${TF}
    echo "Created with [markdown_helper](https://github.com/BurdetteLamar/markdown_helper)" >> ${TF}
    echo "" >> ${TF}
}
#-----------------------------------------

gen_license_file
write_md_line "toc.md"

for file in ./*.md
do
    FILENAME=$(basename $file)
    write_md_line "${FILENAME}"
done
write_footer

${MH} create_page_toc --pristine ${TF} TOC.MD
${MH} include --pristine ${TF} ALL.MD
${MH} create_page_toc --pristine ALL.MD TOC.MD
${MH} include --pristine ${TF} ../README.md
${RM} TOC.MD ALL.MD ${TF}
popd
