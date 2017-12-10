#!/bin/sh
########################################################################
# use release profile to sign the articats and deploy
# muquit@muquit.com Dec-10-2017 
########################################################################

mvn -DperformRelease=true -Dgpg.passphrase="${MY_GPG_PASSPHRASE}" clean deploy
