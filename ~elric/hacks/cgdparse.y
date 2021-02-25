%{
#include <stdio.h>

#include "params.h"
#include "utils.h"

extern char *yytext;
extern int yylineno;

int yylex(void);
int yyerror(char *);

static void string_print2(char *, string_t *);

struct params *yy_global_params;

%}
%union {
	int	 	 integer;
	string_t	*string;
	bits_t		*bits;
	struct params	*params;
	struct keygen	*keygen;
}

%type <params>	entry rules rule
%type <keygen>	keygenrule keygenvars keygenvar deprecated
%type <string>	stringlit base64
%type <bits>	bits

%token <integer> INTEGER
%token <string> STRINGLIT

%token <string> ALGORITHM KEYLENGTH IVMETHOD VERIFY_METHOD

%token <string> KEYGEN
%token <string> METHOD SALT ITERATIONS KEY

%token EOL

/* Deprecated tokens */
%token <string> KEYGEN_METHOD KEYGEN_SALT KEYGEN_ITERATIONS XOR_KEY

%%

entry:	  rules				{ yy_global_params = $$; }

rules:	/* empty */			{ $$ = NULL; }
	| rules rule			{ $$ = params_combine($$, $2); }

rule:	  ALGORITHM stringlit EOL	{ $$ = params_algorithm($2); }
	| KEYLENGTH INTEGER EOL		{ $$ = params_keylen($2); }
	| IVMETHOD stringlit EOL	{ $$ = params_ivmeth($2); }
	| VERIFY_METHOD stringlit EOL	{ $$ = params_verify_method($2); }
	| keygenrule			{ $$ = params_keygen($1); }
/*	| deprecated			{ $$ = params_dep_keygen($1); } */
	| EOL				{ $$ = NULL; }

keygenrule:
	  KEYGEN '{' keygenvars '}' EOL	{ $$ = $3; }

keygenvars: /* empty */			{ $$ = NULL; }
	| keygenvars keygenvar		{ $$ = keygen_combine($$, $2); }

keygenvar: METHOD stringlit EOL		{ $$ = keygen_method($2); }
	|  SALT bits EOL		{ $$ = keygen_salt($2); }
	|  ITERATIONS INTEGER EOL	{ $$ = keygen_iterations($2); }
	|  KEY bits EOL			{ $$ = keygen_key($2); }
	|  EOL				{ $$ = NULL; }

/* The following rules are deprecated */

deprecated:
	  KEYGEN_METHOD stringlit EOL	{ $$ = keygen_method($2); }
	| KEYGEN_SALT bits EOL		{ $$ = keygen_salt($2); }
	| KEYGEN_ITERATIONS INTEGER EOL	{ $$ = keygen_iterations($2); }
	| XOR_KEY bits EOL		{ $$ = keygen_key($2); }

stringlit:  STRINGLIT
	| KEYGEN_SALT

bits:	  base64			{ $$ = bits_decode_d($1); }

base64:   stringlit
	| base64 stringlit		{ $$ = string_add_d($1, $2); }

%%

extern FILE *yyin;

struct params *
cgdparsefile(FILE *f)
{

	yyin = f;
	yyparse();
	return yy_global_params;
}
