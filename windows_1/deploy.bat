cd C:\cygwin\home\Administrator\share\so2\teme-so2\windows_1
nmake clean && nmake
cd checker
rm -rf objchk_wnet_x86
cp  -r ../objchk_wnet_x86 .
cd ../
