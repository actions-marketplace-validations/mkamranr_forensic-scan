; Macro definitions. v1 does not expand macros -- that needs a preprocessor --
; but a #define whose body hides a call or a string is worth surfacing.
(preproc_def name: (identifier) @name value: (preproc_arg) @value) @macro
(preproc_function_def name: (identifier) @name value: (preproc_arg) @value) @macro
