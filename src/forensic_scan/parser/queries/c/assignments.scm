(assignment_expression left: (identifier) @target right: (_) @value) @assign
(init_declarator declarator: (identifier) @target value: (_) @value) @assign
; `const char *cmd = "..."` -- the declarator is a pointer, not a bare identifier.
(init_declarator
  declarator: (pointer_declarator declarator: (identifier) @target)
  value: (_) @value) @assign
(init_declarator
  declarator: (array_declarator declarator: (identifier) @target)
  value: (_) @value) @assign
