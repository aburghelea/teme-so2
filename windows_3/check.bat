set orig="%cd%"
cd checker
nmake /f NMakefile.checker clean
nmake /f NMakefile.checker
driver unload ssr
cd %orig%
checker\test

