// TODO Basic missing features:
// 	- Other list operations: add, insert, insert_many, delete, delete_many, delete_last, delete_all.
// 	- Maps: T[int], T[str].
// 	- Control flow: break, continue.
// 	- Other operators: remainder, bitwise shifts, unary minus, bitwise AND/OR/XOR/NOT, ternary.
// 	- Enums, bitsets.

// TODO Larger missing features:
// 	- Coroutines.
// 	- Serialization.
// 	- Debugging.
// 	- Verbose mode, where every external call is logged, every variable modification is logged, every line is logged, etc? Saving output to file.

// TODO Cleanup:
// 	- Cleanup the code in External- functions and ScriptExecuteFunction using macros for common stack and heap operations.
// 	- Cleanup the ImportData/ExecutionContext/FunctionBuilder structures and their relationships.
// 	- Cleanup the variables/stack arrays.
// 	- Cleanup the platform layer.

// TODO Safety:
// 	- Safety against extremely large scripts?
// 	- Loading untrusted bytecode files?

// TODO Miscellaneous:
// 	- Inlining small strings.
// 	- Exponent notation in numeric literals.
// 	- Block comments.
// 	- More escape sequences in string literals.
// 	- Setting the initial values of global variables.
// 	- Better handling of memory allocation failures.

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define T_ERROR               (0)

#define T_EOF                 (1)
#define T_IDENTIFIER          (2)
#define T_STRING_LITERAL      (3)
#define T_NUMERIC_LITERAL     (4)

#define T_ADD                 (40)
#define T_MINUS               (41)
#define T_ASTERISK            (42)
#define T_SLASH               (43)
#define T_LEFT_ROUND          (44)
#define T_RIGHT_ROUND         (45)
#define T_LEFT_SQUARE         (46)
#define T_RIGHT_SQUARE        (47)
#define T_LEFT_FANCY          (48)
#define T_RIGHT_FANCY         (49)
#define T_COMMA               (50)
#define T_EQUALS              (51)
#define T_SEMICOLON           (52)
#define T_GREATER_THAN        (53)
#define T_LESS_THAN           (54)
#define T_GT_OR_EQUAL         (55)
#define T_LT_OR_EQUAL         (56)
#define T_DOUBLE_EQUALS       (57)
#define T_NOT_EQUALS          (58)
#define T_LOGICAL_AND         (59)
#define T_LOGICAL_OR          (60)
#define T_ADD_EQUALS          (61)
#define T_MINUS_EQUALS        (62)
#define T_ASTERISK_EQUALS     (63)
#define T_SLASH_EQUALS        (64)
#define T_DOT                 (65)
#define T_COLON               (66)
#define T_LOGICAL_NOT         (67)

#define T_ROOT                (80)
#define T_FUNCBODY            (81)
#define T_ARGUMENTS           (82)
#define T_ARGUMENT            (83)
#define T_FUNCTION            (84)
#define T_BLOCK               (85)
#define T_VARIABLE            (86)
#define T_CALL                (87)
#define T_DECLARE             (88)
#define T_FUNCPTR             (89)
#define T_STR_INTERPOLATE     (90)
#define T_INDEX               (91)
#define T_LIST                (92)
#define T_IMPORT_PATH         (93)

#define T_EXIT_SCOPE          (100)
#define T_END_FUNCTION        (101)
#define T_POP                 (102)
#define T_BRANCH              (103)
#define T_CONCAT              (104)
#define T_INTERPOLATE_STR     (105)
#define T_INTERPOLATE_BOOL    (106)
#define T_INTERPOLATE_INT     (107)
#define T_INTERPOLATE_FLOAT   (108)

#define T_FLOAT_ADD           (120)
#define T_FLOAT_MINUS         (121)
#define T_FLOAT_ASTERISK      (122)
#define T_FLOAT_SLASH         (123)
#define T_FLOAT_GREATER_THAN  (124)
#define T_FLOAT_LESS_THAN     (125)
#define T_FLOAT_GT_OR_EQUAL   (126)
#define T_FLOAT_LT_OR_EQUAL   (127)
#define T_FLOAT_DOUBLE_EQUALS (128)
#define T_FLOAT_NOT_EQUALS    (129)
#define T_STR_DOUBLE_EQUALS   (130)
#define T_STR_NOT_EQUALS      (131)
#define T_EQUALS_DOT          (132)
#define T_EQUALS_LIST         (133)
#define T_INDEX_LIST          (134)

#define T_OP_RESIZE           (140)
#define T_OP_ADD              (141)
#define T_OP_INSERT           (142)
#define T_OP_INSERT_MANY      (143)
#define T_OP_DELETE           (144)
#define T_OP_DELETE_MANY      (145)
#define T_OP_DELETE_LAST      (146)
#define T_OP_DELETE_ALL       (147)
#define T_OP_FIRST            (148)
#define T_OP_LAST             (149)
#define T_OP_LEN              (150)

#define T_IF                  (160)
#define T_WHILE               (161)
#define T_FOR                 (162)
#define T_INT                 (163)
#define T_FLOAT               (164)
#define T_BOOL                (165)
#define T_VOID                (166)
#define T_RETURN              (167)
#define T_ELSE                (168)
#define T_EXTCALL             (169)
#define T_STR                 (170)
#define T_FUNCTYPE            (171)
#define T_NULL                (172)
#define T_FALSE               (173)
#define T_TRUE                (174)
#define T_ASSERT              (175)
#define T_PERSIST             (176)
#define T_STRUCT              (177)
#define T_NEW                 (178)
#define T_OPTION              (179)
#define T_IMPORT              (180)
#define T_INLINE              (181)

typedef struct Token {
	struct ImportData *module;
	const char *text;
	size_t textBytes;
	uint32_t line;
	uint8_t type;
} Token;

typedef struct Tokenizer {
	struct ImportData *module;
	const char *input;
	size_t inputBytes;
	uintptr_t position;
	uintptr_t line;
	bool error, isBaseModule;
} Tokenizer;

typedef struct Scope {
	struct Node **entries;
	size_t entryCount;
	size_t variableEntryCount;
	size_t entriesAllocated;
	bool isRoot;
} Scope;

typedef struct Node {
	uint8_t type;
	bool referencesRootScope, isExternalCall, isPersistentVariable, isOptionVariable;
	uint8_t operationType;
	int32_t inlineImportVariableIndex;
	Token token;
	struct Node *firstChild;
	struct Node *sibling;
	struct Node *parent; // Set in ASTSetScopes.
	Scope *scope; // Set in ASTSetScopes.
	struct Node *resolveAs; // Set in ASTLookupTypeIdentifiers.
	struct Node *expressionType; // Set in ASTSetTypes.
	struct ImportData *importData;
} Node;

typedef struct Value {
	union {
		int64_t i;
		double f;
	};
} Value;

typedef struct LineNumber {
	struct ImportData *importData;
	uint32_t instructionPointer;
	uint32_t lineNumber;
	Token *function;
} LineNumber;

typedef struct FunctionBuilder {
	uint8_t *data;
	size_t dataBytes;
	size_t dataAllocated;
	LineNumber *lineNumbers;
	size_t lineNumberCount;
	size_t lineNumbersAllocated;
	int32_t scopeIndex;
	bool isPersistentVariable, isDotAssignment, isListAssignment;
	uintptr_t globalVariableOffset;
	struct ImportData *importData; // Only valid during script loading.
} FunctionBuilder;

typedef struct BackTraceLink {
	struct BackTraceLink *previous;
	uint32_t instructionPointer;
} BackTraceLink;

typedef struct HeapEntry {
	uint8_t type;
	bool gcMark;
	bool listValuesAreManaged;

	union {
		struct {
			// TODO Inlining small strings.
			size_t bytes;
			char *text;
		};

		struct {
			uint16_t fieldCount;
			Value *fields; // Managed bools placed before this.
		};

		struct {
			uint32_t length, allocated;
			Value *list;
		};

		struct {
			uintptr_t nextUnusedEntry;
		};
	};
} HeapEntry;

typedef struct ExecutionContext {
	Value *variables;
	bool *variableIsManaged;
	size_t variableCount;
	size_t variablesAllocated;
	Value stack[50]; // TODO Merge with variables?
	bool stackIsManaged[50];
	uintptr_t stackPointer;
	size_t stackEntriesAllocated;
	HeapEntry *heap;
	uintptr_t heapFirstUnusedEntry;
	size_t heapEntriesAllocated;
	FunctionBuilder *functionData; // Cleanup the relations between ExecutionContext, FunctionBuilder, Tokenizer and ImportData.
	BackTraceLink *backTrace;
	Node *rootNode; // Only valid during script loading.
	char *scriptPersistFile;
	struct ImportData *mainModule;
} ExecutionContext;

typedef struct ExternalFunction {
	const char *cName;
	int (*callback)(ExecutionContext *context, Value *returnValue);
} ExternalFunction;

typedef struct ImportData {
	char *path;
	size_t pathBytes;
	void *fileData;
	size_t fileDataBytes;
	uintptr_t globalVariableOffset;
	struct ImportData *nextImport;
	struct ImportData *parentImport;
	Node *rootNode;
} ImportData;

Node globalExpressionTypeVoid = { .type = T_VOID };
Node globalExpressionTypeInt = { .type = T_INT };
Node globalExpressionTypeFloat = { .type = T_FLOAT };
Node globalExpressionTypeBool = { .type = T_BOOL };
Node globalExpressionTypeStr = { .type = T_STR };

// Global variables:
char *scriptSourceDirectory;
char **options;
bool *optionsMatched;
size_t optionCount;
ImportData *importedModules;
ImportData **importedModulesLink = &importedModules;

// Forward declarations:
Node *ParseBlock(Tokenizer *tokenizer);
Node *ParseExpression(Tokenizer *tokenizer, bool allowAssignment, uint8_t precedence);
void ScriptPrintNode(Node *node, int indent);
bool ScriptLoad(Tokenizer tokenizer, ExecutionContext *context, ImportData *importData);
uintptr_t HeapAllocate(ExecutionContext *context);

// --------------------------------- Platform layer definitions.

#include <assert.h>
#define Assert assert

void *AllocateFixed(size_t bytes);
void *AllocateResize(void *old, size_t bytes);
int MemoryCompare(const void *a, const void *b, size_t bytes);
void MemoryCopy(void *a, const void *b, size_t bytes);
size_t PrintIntegerToBuffer(char *buffer, size_t bufferBytes, int64_t i); // TODO This shouldn't be in the platform layer.
size_t PrintFloatToBuffer(char *buffer, size_t bufferBytes, double f); // TODO This shouldn't be in the platform layer.
void PrintDebug(const char *format, ...);
void PrintError(Tokenizer *tokenizer, const char *format, ...);
void PrintError2(Tokenizer *tokenizer, Node *node, const char *format, ...);
void PrintError3(const char *format, ...);
void PrintError4(ExecutionContext *context, uint32_t instructionPointer, const char *format, ...);
void *FileLoad(const char *path, size_t *length);

// --------------------------------- Base module.

#define BASE_MODULE_SOURCE \
	"void PrintStdErr(str x) #extcall;" \
	"void PrintStdErrWarning(str x) #extcall;" \
	"void PrintStdErrHighlight(str x) #extcall;" \
	"str ConsoleGetLine() #extcall;" \
	"str StringTrim(str x) #extcall;" \
	"int StringToByte(str x) #extcall;" \
	"bool SystemShellExecute(str x) #extcall;" /* Returns true on success. */ \
	"bool SystemShellExecuteWithWorkingDirectory(str wd, str x) #extcall;" /* Returns true on success. */ \
	"str SystemShellEvaluate(str x) #extcall;" \
	"int SystemGetProcessorCount() #extcall;" \
	"str SystemGetEnvironmentVariable(str name) #extcall;" \
	"bool SystemSetEnvironmentVariable(str name, str value) #extcall;" \
	"bool PathExists(str x) #extcall;" \
	"bool PathCreateDirectory(str x) #extcall;" /* TODO Replace the return value with a enum. */ \
	"bool PathDelete(str x) #extcall;" /* TODO Replace the return value with a enum. */ \
	"bool PathDeleteRecursively(str x) #extcall;" \
	"bool PathMove(str source, str destination) #extcall;" \
	"str PathGetDefaultPrefix() #extcall;" \
	"bool PathSetDefaultPrefixToScriptSourceDirectory() #extcall;" \
	"str FileReadAll(str path) #extcall;" /* TODO Returning an error? */ \
	"bool FileWriteAll(str path, str x) #extcall;" /* TODO Returning an error? */ \
	"bool FileCopy(str source, str destination) #extcall;" \
	"bool PersistRead(str path) #extcall;" \
	\
	"bool StringContains(str haystack, str needle) {" \
	"	for int i = 0; i <= haystack:len() - needle:len(); i += 1 {" \
	"		bool match = true;" \
	"		for int j = 0; j < needle:len(); j += 1 { if haystack[i + j] != needle[j] match = false; }" \
	"		if match { return true; }" \
	"	}" \
	"" \
	"	return false;" \
	"}" \
	""\
	"bool CharacterIsAlnum(str c) {" \
	"	int b = StringToByte(c);" \
	"	return (b >= StringToByte(\"A\") && b <= StringToByte(\"Z\")) || (b >= StringToByte(\"a\") && b <= StringToByte(\"z\"))" \
	"		|| (b >= StringToByte(\"0\") && b <= StringToByte(\"9\"));" \
	"}" \


// --------------------------------- External function calls.

int ExternalPrintInt(ExecutionContext *context, Value *returnValue);
int ExternalPrintString(ExecutionContext *context, Value *returnValue);
int ExternalPrintStdErr(ExecutionContext *context, Value *returnValue);
int ExternalPrintStdErrWarning(ExecutionContext *context, Value *returnValue);
int ExternalPrintStdErrHighlight(ExecutionContext *context, Value *returnValue);
int ExternalConsoleGetLine(ExecutionContext *context, Value *returnValue);
int ExternalStringTrim(ExecutionContext *context, Value *returnValue);
int ExternalStringToByte(ExecutionContext *context, Value *returnValue);
int ExternalSystemShellExecute(ExecutionContext *context, Value *returnValue);
int ExternalSystemShellExecuteWithWorkingDirectory(ExecutionContext *context, Value *returnValue);
int ExternalSystemShellEvaluate(ExecutionContext *context, Value *returnValue);
int ExternalSystemGetProcessorCount(ExecutionContext *context, Value *returnValue);
int ExternalSystemGetEnvironmentVariable(ExecutionContext *context, Value *returnValue);
int ExternalSystemSetEnvironmentVariable(ExecutionContext *context, Value *returnValue);
int ExternalPathCreateDirectory(ExecutionContext *context, Value *returnValue);
int ExternalPathDelete(ExecutionContext *context, Value *returnValue);
int ExternalPathDeleteRecursively(ExecutionContext *context, Value *returnValue);
int ExternalPathExists(ExecutionContext *context, Value *returnValue);
int ExternalPathMove(ExecutionContext *context, Value *returnValue);
int ExternalPathGetDefaultPrefix(ExecutionContext *context, Value *returnValue);
int ExternalPathSetDefaultPrefixToScriptSourceDirectory(ExecutionContext *context, Value *returnValue);
int ExternalFileReadAll(ExecutionContext *context, Value *returnValue);
int ExternalFileWriteAll(ExecutionContext *context, Value *returnValue);
int ExternalFileCopy(ExecutionContext *context, Value *returnValue);
int ExternalPersistRead(ExecutionContext *context, Value *returnValue);
int ExternalPersistWrite(ExecutionContext *context, Value *returnValue);

ExternalFunction externalFunctions[] = {
	{ .cName = "PrintStdErr", .callback = ExternalPrintStdErr },
	{ .cName = "PrintStdErrWarning", .callback = ExternalPrintStdErrWarning },
	{ .cName = "PrintStdErrHighlight", .callback = ExternalPrintStdErrHighlight },
	{ .cName = "ConsoleGetLine", .callback = ExternalConsoleGetLine },
	{ .cName = "StringTrim", .callback = ExternalStringTrim },
	{ .cName = "StringToByte", .callback = ExternalStringToByte },
	{ .cName = "SystemShellExecute", .callback = ExternalSystemShellExecute },
	{ .cName = "SystemShellExecuteWithWorkingDirectory", .callback = ExternalSystemShellExecuteWithWorkingDirectory },
	{ .cName = "SystemShellEvaluate", .callback = ExternalSystemShellEvaluate },
	{ .cName = "SystemGetProcessorCount", .callback = ExternalSystemGetProcessorCount },
	{ .cName = "SystemGetEnvironmentVariable", .callback = ExternalSystemGetEnvironmentVariable },
	{ .cName = "SystemSetEnvironmentVariable", .callback = ExternalSystemSetEnvironmentVariable },
	{ .cName = "PathExists", .callback = ExternalPathExists },
	{ .cName = "PathCreateDirectory", .callback = ExternalPathCreateDirectory },
	{ .cName = "PathDelete", .callback = ExternalPathDelete },
	{ .cName = "PathDeleteRecursively", .callback = ExternalPathDeleteRecursively },
	{ .cName = "PathMove", .callback = ExternalPathMove },
	{ .cName = "PathGetDefaultPrefix", .callback = ExternalPathGetDefaultPrefix },
	{ .cName = "PathSetDefaultPrefixToScriptSourceDirectory", .callback = ExternalPathSetDefaultPrefixToScriptSourceDirectory },
	{ .cName = "FileReadAll", .callback = ExternalFileReadAll },
	{ .cName = "FileWriteAll", .callback = ExternalFileWriteAll },
	{ .cName = "FileCopy", .callback = ExternalFileCopy },
	{ .cName = "PersistRead", .callback = ExternalPersistRead },
	{ .cName = "PersistWrite", .callback = ExternalPersistWrite },
};

// --------------------------------- Tokenization and parsing.

uint8_t TokenLookupPrecedence(uint8_t t) {
	if (t == T_EQUALS)          return 10;
	if (t == T_ADD_EQUALS)      return 10;
	if (t == T_MINUS_EQUALS)    return 10;
	if (t == T_ASTERISK_EQUALS) return 10;
	if (t == T_SLASH_EQUALS)    return 10;
	if (t == T_LOGICAL_OR)      return 14;
	if (t == T_LOGICAL_AND)     return 15;
	if (t == T_GREATER_THAN)    return 20;
	if (t == T_LESS_THAN)       return 20;
	if (t == T_GT_OR_EQUAL)     return 20;
	if (t == T_LT_OR_EQUAL)     return 20;
	if (t == T_DOUBLE_EQUALS)   return 20;
	if (t == T_NOT_EQUALS)      return 20;
	if (t == T_ADD)             return 50;
	if (t == T_MINUS)           return 50;
	if (t == T_ASTERISK)        return 60;
	if (t == T_SLASH)           return 60;
	if (t == T_DOT)             return 80;
	if (t == T_COLON)           return 80;
	if (t == T_LOGICAL_NOT)     return 90;
	if (t == T_LEFT_ROUND)      return 100;
	Assert(false);
}

Token TokenNext(Tokenizer *tokenizer) {
	// TODO Block comments.

	Token token = { 0 };
	token.type = T_ERROR;
	token.module = tokenizer->module;

	while (true) {
		if (tokenizer->position == tokenizer->inputBytes) {
			token.type = T_EOF;
			break;
		}

		uint8_t c = tokenizer->input[tokenizer->position];
		uint8_t c1 = tokenizer->position + 1 == tokenizer->inputBytes ? 0 : tokenizer->input[tokenizer->position + 1];
		token.text = &tokenizer->input[tokenizer->position];
		token.textBytes = 1;
		token.line = tokenizer->line;

		if (c == ' ' || c == '\t' || c == '\r') { 
			tokenizer->position++; 
			continue; 
		} else if (c == '\n') {
			tokenizer->position++; 
			tokenizer->line++;
			continue; 
		} else if (c == '/' && c1 == '/') {
			while (tokenizer->position != tokenizer->inputBytes && tokenizer->input[tokenizer->position] != '\n') {
				tokenizer->position++;
			}

			continue;
		}

		else if (c == '<' && c1 == '=' && (tokenizer->position += 2)) token.type = T_LT_OR_EQUAL;
		else if (c == '>' && c1 == '=' && (tokenizer->position += 2)) token.type = T_GT_OR_EQUAL;
		else if (c == '=' && c1 == '=' && (tokenizer->position += 2)) token.type = T_DOUBLE_EQUALS;
		else if (c == '!' && c1 == '=' && (tokenizer->position += 2)) token.type = T_NOT_EQUALS;
		else if (c == '&' && c1 == '&' && (tokenizer->position += 2)) token.type = T_LOGICAL_AND;
		else if (c == '|' && c1 == '|' && (tokenizer->position += 2)) token.type = T_LOGICAL_OR;
		else if (c == '+' && c1 == '=' && (tokenizer->position += 2)) token.type = T_ADD_EQUALS;
		else if (c == '-' && c1 == '=' && (tokenizer->position += 2)) token.type = T_MINUS_EQUALS;
		else if (c == '*' && c1 == '=' && (tokenizer->position += 2)) token.type = T_ASTERISK_EQUALS;
		else if (c == '/' && c1 == '=' && (tokenizer->position += 2)) token.type = T_SLASH_EQUALS;
		else if (c == '+' && ++tokenizer->position) token.type = T_ADD;
		else if (c == '-' && ++tokenizer->position) token.type = T_MINUS;
		else if (c == '*' && ++tokenizer->position) token.type = T_ASTERISK;
		else if (c == '/' && ++tokenizer->position) token.type = T_SLASH;
		else if (c == '(' && ++tokenizer->position) token.type = T_LEFT_ROUND;
		else if (c == ')' && ++tokenizer->position) token.type = T_RIGHT_ROUND;
		else if (c == '[' && ++tokenizer->position) token.type = T_LEFT_SQUARE;
		else if (c == ']' && ++tokenizer->position) token.type = T_RIGHT_SQUARE;
		else if (c == '{' && ++tokenizer->position) token.type = T_LEFT_FANCY;
		else if (c == '}' && ++tokenizer->position) token.type = T_RIGHT_FANCY;
		else if (c == ',' && ++tokenizer->position) token.type = T_COMMA;
		else if (c == ';' && ++tokenizer->position) token.type = T_SEMICOLON;
		else if (c == '=' && ++tokenizer->position) token.type = T_EQUALS;
		else if (c == '<' && ++tokenizer->position) token.type = T_LESS_THAN;
		else if (c == '>' && ++tokenizer->position) token.type = T_GREATER_THAN;
		else if (c == '%' && ++tokenizer->position) token.type = T_STR_INTERPOLATE;
		else if (c == '.' && ++tokenizer->position) token.type = T_DOT;
		else if (c == ':' && ++tokenizer->position) token.type = T_COLON;
		else if (c == '!' && ++tokenizer->position) token.type = T_LOGICAL_NOT;

		else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_') || (c >= 0x80) || c == '#') {
			token.textBytes = 0;
			token.type = T_IDENTIFIER;
			token.text = tokenizer->input + tokenizer->position;

			while ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') 
					|| (c == '_') || (c >= 0x80) || (c == '#' && !token.textBytes)) {
				tokenizer->position++;
				token.textBytes++;
				if (tokenizer->position == tokenizer->inputBytes) break;
				c = tokenizer->input[tokenizer->position];
			}

#define KEYWORD(x) (token.textBytes == sizeof(x) - 1 && 0 == MemoryCompare(x, token.text, token.textBytes))
			if KEYWORD("if") token.type = T_IF;
			else if KEYWORD("else") token.type = T_ELSE;
			else if KEYWORD("while") token.type = T_WHILE;
			else if KEYWORD("for") token.type = T_FOR;
			else if KEYWORD("int") token.type = T_INT;
			else if KEYWORD("float") token.type = T_FLOAT;
			else if KEYWORD("str") token.type = T_STR;
			else if KEYWORD("bool") token.type = T_BOOL;
			else if KEYWORD("void") token.type = T_VOID;
			else if KEYWORD("return") token.type = T_RETURN;
			else if KEYWORD("#extcall") token.type = T_EXTCALL;
			else if KEYWORD("functype") token.type = T_FUNCTYPE;
			else if KEYWORD("null") token.type = T_NULL;
			else if KEYWORD("false") token.type = T_FALSE;
			else if KEYWORD("true") token.type = T_TRUE;
			else if KEYWORD("assert") token.type = T_ASSERT;
			else if KEYWORD("#persist") token.type = T_PERSIST;
			else if KEYWORD("struct") token.type = T_STRUCT;
			else if KEYWORD("new") token.type = T_NEW;
			else if KEYWORD("#option") token.type = T_OPTION;
			else if KEYWORD("#import") token.type = T_IMPORT;
			else if KEYWORD("#inline") token.type = T_INLINE;

			else if (token.text[0] == '#') {
				PrintError(tokenizer, "Unrecognised #-token '%.*s'.\n", token.textBytes, token.text);
				tokenizer->error = true;
				token.type = T_ERROR;
				break;
			}
		} else if (c >= '0' && c <= '9') {
			// TODO Exponent notation.

			token.textBytes = 0;
			token.type = T_NUMERIC_LITERAL;
			token.text = tokenizer->input + tokenizer->position;

			while ((c >= '0' && c <= '9') || (c == '.')) {
				tokenizer->position++;
				token.textBytes++;
				if (tokenizer->position == tokenizer->inputBytes) break;
				c = tokenizer->input[tokenizer->position];
			}
		} else if (c == '"') {
			// TODO Escape sequence to insert an arbitrary codepoint.

			bool inInterpolation = false;
			intptr_t startPosition = ++tokenizer->position;
			intptr_t endPosition = -1;
			
			for (uintptr_t i = tokenizer->position; true; i++) {
				if (inInterpolation) {
					if (tokenizer->input[i] == '%') {
						inInterpolation = false;
					} else if (tokenizer->input[i] == '"') {
						PrintError(tokenizer, "Strings are not allowed within a string interpolation expression.\n");
						tokenizer->error = true;
						break;
					} else if (tokenizer->input[i] == '\n') {
						PrintError(tokenizer, "String interpolation expressions must stay on a single line.\n");
						tokenizer->error = true;
						break;
					} else {
						token.textBytes++;
					}
				} else if (i == tokenizer->inputBytes || tokenizer->input[i] == '\n') {
					PrintError(tokenizer, "String does not end before the end of the line.\n");
					tokenizer->error = true;
					break;
				} else if (tokenizer->input[i] == '"') {
					endPosition = i;
					break;
				} else if (tokenizer->input[i] == '%') {
					inInterpolation = true;
				} else if (tokenizer->input[i] == '\\') {
					if (i + 1 == tokenizer->inputBytes 
							|| (tokenizer->input[i + 1] != 'n' && tokenizer->input[i + 1] != 't' 
								&& tokenizer->input[i + 1] != '%' 
								&& tokenizer->input[i + 1] != '"' && tokenizer->input[i + 1] != '\\')) {
						PrintError(tokenizer, "String contains unrecognized escape sequence '\\%c'. "
								"Possibilities are: '\\\\', '\\%', '\\n', '\\t' and '\\\"'\n", tokenizer->input[i + 1]);
						tokenizer->error = true;
						break;
					} else {
						i++;
						token.textBytes++;
					}
				} else {
					token.textBytes++;
				}
			}

			if (endPosition != -1) {
				token.text = tokenizer->input + startPosition;
				token.textBytes = endPosition - startPosition;
				token.type = T_STRING_LITERAL;
				tokenizer->position = endPosition + 1;
			}
		} else {
			PrintError(tokenizer, "Unexpected character '%c'.\n", c);
			tokenizer->error = true;
		}

		break;
	}

	return token;
}

Token TokenPeek(Tokenizer *tokenizer) {
	Tokenizer copy = *tokenizer;
	return TokenNext(&copy);
}

Node *ParseType(Tokenizer *tokenizer, bool maybe, bool allowVoid) {
	Node *node = (Node *) AllocateFixed(sizeof(Node));
	node->token = TokenNext(tokenizer);

	if (node->token.type == T_INT 
			|| node->token.type == T_FLOAT 
			|| node->token.type == T_STR 
			|| node->token.type == T_BOOL 
			|| node->token.type == T_VOID 
			|| node->token.type == T_IDENTIFIER) {
		node->type = node->token.type;

		if (!allowVoid && node->type == T_VOID) {
			PrintError2(tokenizer, node, "The 'void' type is not allowed here.\n");
			return NULL;
		}

		bool first = true;

		while (true) {
			Token token = TokenPeek(tokenizer);

			if (token.type == T_ERROR) {
				return NULL;
			} else if (token.type == T_LEFT_SQUARE) {
				Node *list = (Node *) AllocateFixed(sizeof(Node));
				list->type = T_LIST;
				list->token = TokenNext(tokenizer);

				if (first) {
					list->firstChild = node;
					first = false;
					node = list;
				} else {
					Node *end = node;
					while (end->firstChild->firstChild) end = end->firstChild;
					list->firstChild = end->firstChild;
					end->firstChild = list;
				}

				token = TokenNext(tokenizer);

				if (token.type == T_ERROR) {
					return NULL;
				} else if (token.type != T_RIGHT_SQUARE) {
					if (!maybe) {
						PrintError2(tokenizer, node, "Expected a ']' after the '[' in an list type.\n");
					}

					return NULL;
				}
			} else {
				break;
			}
		}

		return node;
	} else if (!maybe) {
		PrintError2(tokenizer, node, "Expected a type. This can be 'int', 'float', 'bool', 'void', 'str', or an identifier.\n");
		return NULL;
	} else {
		return NULL;
	}
}

Node *ParseCall(Tokenizer *tokenizer, Node *function) {
	Node *call = (Node *) AllocateFixed(sizeof(Node));
	call->token = TokenNext(tokenizer);
	call->type = T_CALL;
	call->firstChild = function;
	Node *arguments = (Node *) AllocateFixed(sizeof(Node));
	arguments->type = T_ARGUMENTS;
	function->sibling = arguments;
	Node **link = &arguments->firstChild;

	if (call->token.type != T_LEFT_ROUND) {
		PrintError2(tokenizer, call, "Expected a '(' to start the list of arguments.\n");
		return NULL;
	}

	while (true) {
		Token token = TokenPeek(tokenizer);

		if (token.type == T_RIGHT_ROUND) {
			TokenNext(tokenizer);
			break;
		}

		if (arguments->firstChild) {
			Token comma = TokenNext(tokenizer);

			if (comma.type != T_COMMA) {
				Node n = { .token = comma };
				PrintError2(tokenizer, &n, "Expected a comma to separate function arguments.\n");
				return NULL;
			}
		}

		Node *argument = ParseExpression(tokenizer, false, 0);
		if (!argument) return NULL;
		*link = argument;
		link = &argument->sibling;
	}

	return call;
}

Node *ParseExpression(Tokenizer *tokenizer, bool allowAssignment, uint8_t precedence) {
	Node *node = (Node *) AllocateFixed(sizeof(Node));
	node->token = TokenNext(tokenizer);
	if (node->token.type == T_ERROR) return NULL;

	if (node->token.type == T_IDENTIFIER) {
		node->type = T_VARIABLE;
	} else if (node->token.type == T_STRING_LITERAL) {
		Node *string = node;
		string->type = string->token.type;

		const char *raw = string->token.text;
		size_t rawBytes = string->token.textBytes;

		// It's impossible for size of the string to increase.
		char *output = AllocateFixed(rawBytes);
		size_t outputPosition = 0;

		string->token.text = output;
		string->token.textBytes = 0;

		for (uintptr_t i = 0; i < rawBytes; i++) {
			char c = raw[i];

			if (c == '\\') {
				Assert(i != rawBytes - 1);
				c = raw[++i];
				Assert(outputPosition != rawBytes);
				if (c == '\\') c = '\\';
				else if (c == 'n') c = '\n';
				else if (c == 't') c = '\t';
				else if (c == '%') c = '%';
				else if (c == '"') c = '"';
				else Assert(false);
				output[outputPosition++] = c;
				string->token.textBytes++;
			} else if (c == '%') {
				Node *stringInterpolate = (Node *) AllocateFixed(sizeof(Node));
				stringInterpolate->type = T_STR_INTERPOLATE;
				stringInterpolate->firstChild = node;
				Tokenizer t = *tokenizer;
				t.position = raw - t.input + i + 1;
				stringInterpolate->firstChild->sibling = ParseExpression(&t, false, 0);
				if (!stringInterpolate->firstChild->sibling) return NULL;
				i = t.position - (raw - t.input);
				string = (Node *) AllocateFixed(sizeof(Node));
				string->type = T_STRING_LITERAL;
				string->token.text = output + outputPosition;
				string->token.textBytes = 0;
				stringInterpolate->firstChild->sibling->sibling = string;
				node = stringInterpolate;
			} else {
				Assert(outputPosition != rawBytes);
				output[outputPosition++] = c;
				string->token.textBytes++;
			}
		}
	} else if (node->token.type == T_NUMERIC_LITERAL
			|| node->token.type == T_TRUE || node->token.type == T_FALSE || node->token.type == T_NULL) {
		node->type = node->token.type;
	} else if (node->token.type == T_LOGICAL_NOT) {
		node->type = node->token.type;
		node->firstChild = ParseExpression(tokenizer, false, TokenLookupPrecedence(node->token.type));
	} else if (node->token.type == T_LEFT_ROUND) {
		node = ParseExpression(tokenizer, false, 0);
		if (!node) return NULL;

		Token token = TokenNext(tokenizer);

		if (token.type != T_RIGHT_ROUND) {
			Node n = { .token = token };
			PrintError2(tokenizer, &n, "Expected a matching closing bracket.\n");
			return NULL;
		}
	} else if (node->token.type == T_NEW) {
		node->type = T_NEW;
		node->firstChild = ParseType(tokenizer, false, false);
		node->expressionType = node->firstChild;
		if (!node->firstChild) return NULL;
	} else {
		PrintError2(tokenizer, node, "Expected an expression. "
				"Expressions can start with a variable identifier, a string literal, a number, 'len', 'new', '!' or '('.\n");
		return NULL;
	}

	while (true) {
		Token token = TokenPeek(tokenizer);

		if (token.type == T_ERROR) {
			return NULL;
		} else if ((token.type == T_EQUALS || token.type == T_ADD_EQUALS || token.type == T_MINUS_EQUALS 
					|| token.type == T_ASTERISK_EQUALS || token.type == T_SLASH_EQUALS) && !allowAssignment) {
			PrintError2(tokenizer, node, "Variable assignment is not allowed within an expression.\n");
			return NULL;
		} else if (token.type == T_DOT && TokenLookupPrecedence(token.type) > precedence) {
			TokenNext(tokenizer);
			Node *operation = (Node *) AllocateFixed(sizeof(Node));
			operation->token = TokenNext(tokenizer);
			operation->type = T_DOT;
			operation->firstChild = node;
			node = operation;

			if (operation->token.type != T_IDENTIFIER) {
				PrintError2(tokenizer, node, "Expected an identifier for the struct field after '.'.\n");
				return NULL;
			}
		} else if (token.type == T_COLON && TokenLookupPrecedence(token.type) > precedence) {
			TokenNext(tokenizer);
			Token operationName = TokenNext(tokenizer);

			if (operationName.type != T_IDENTIFIER) {
				PrintError2(tokenizer, node, "Expected an identifier for the operation name after ':'.\n");
				return NULL;
			}

			node = ParseCall(tokenizer, node);
			if (!node) return NULL;
			node->type = T_COLON;
			node->token = operationName;
		} else if ((token.type == T_EQUALS || token.type == T_ADD || token.type == T_MINUS
					|| token.type == T_ASTERISK || token.type == T_SLASH
					|| token.type == T_GREATER_THAN || token.type == T_LESS_THAN
					|| token.type == T_LT_OR_EQUAL || token.type == T_GT_OR_EQUAL
					|| token.type == T_DOUBLE_EQUALS || token.type == T_NOT_EQUALS
					|| token.type == T_LOGICAL_AND || token.type == T_LOGICAL_OR) 
				&& TokenLookupPrecedence(token.type) > precedence) {
			Node *operation = (Node *) AllocateFixed(sizeof(Node));
			operation->token = TokenNext(tokenizer);
			operation->type = operation->token.type;
			operation->firstChild = node;
			node->sibling = ParseExpression(tokenizer, false, TokenLookupPrecedence(token.type));
			if (!node->sibling) return NULL;
			node = operation;
		} else if (token.type == T_ADD_EQUALS || token.type == T_MINUS_EQUALS
				|| token.type == T_ASTERISK_EQUALS || token.type == T_SLASH_EQUALS) {
			Node *operation = (Node *) AllocateFixed(sizeof(Node));
			operation->token = TokenNext(tokenizer);
			operation->type = operation->token.type - T_ADD_EQUALS + T_ADD;
			operation->firstChild = node;
			node->sibling = ParseExpression(tokenizer, false, TokenLookupPrecedence(token.type));
			if (!node->sibling) return NULL;
			Node *nodeCopy = AllocateFixed(sizeof(Node));
			*nodeCopy = *node;
			node = operation;
			operation = (Node *) AllocateFixed(sizeof(Node));
			operation->token = token;
			operation->type = T_EQUALS;
			operation->firstChild = nodeCopy;
			operation->firstChild->sibling = node;
			node = operation;
		} else if (token.type == T_LEFT_ROUND && TokenLookupPrecedence(token.type) > precedence) {
			node = ParseCall(tokenizer, node);
			if (!node) return NULL;
		} else if (token.type == T_LEFT_SQUARE) {
			TokenNext(tokenizer);
			Node *index = (Node *) AllocateFixed(sizeof(Node));
			index->type = T_INDEX;
			index->token = token;
			index->firstChild = node;
			index->firstChild->sibling = ParseExpression(tokenizer, false, 0);
			if (!index->firstChild->sibling) return NULL;
			node = index;
			Token token = TokenNext(tokenizer);

			if (token.type != T_RIGHT_SQUARE) {
				Node n = { .token = token };
				PrintError2(tokenizer, &n, "Expected a matching closing bracket.\n");
				return NULL;
			}
		} else {
			break;
		}
	}

	return node;
}

Node *ParseIf(Tokenizer *tokenizer) {
	Node *node = (Node *) AllocateFixed(sizeof(Node));
	node->type = T_IF;
	node->token = TokenNext(tokenizer);
	node->firstChild = ParseExpression(tokenizer, false, 0);
	if (!node->firstChild) return NULL;
	Token token = TokenPeek(tokenizer);

	if (token.type == T_LEFT_FANCY) {
		TokenNext(tokenizer);
		node->firstChild->sibling = ParseBlock(tokenizer);
		if (!node->firstChild->sibling) return NULL;
	} else {
		node->firstChild->sibling = ParseExpression(tokenizer, true, 0);
		if (!node->firstChild->sibling) return NULL;

		Token semicolon = TokenNext(tokenizer);

		if (semicolon.type != T_SEMICOLON) {
			PrintError2(tokenizer, node->firstChild->sibling, "Expected a semicolon at the end of the expression.\n");
			return NULL;
		}
	}

	token = TokenPeek(tokenizer);

	if (token.type == T_ELSE) {
		TokenNext(tokenizer);
		token = TokenPeek(tokenizer);

		if (token.type == T_IF) {
			node->firstChild->sibling->sibling = ParseIf(tokenizer);
			if (!node->firstChild->sibling->sibling) return NULL;
		} else if (token.type == T_LEFT_FANCY) {
			TokenNext(tokenizer);
			node->firstChild->sibling->sibling = ParseBlock(tokenizer);
			if (!node->firstChild->sibling->sibling) return NULL;
		} else {
			node->firstChild->sibling->sibling = ParseExpression(tokenizer, true, 0);
			if (!node->firstChild->sibling->sibling) return NULL;

			Token semicolon = TokenNext(tokenizer);

			if (semicolon.type != T_SEMICOLON) {
				PrintError2(tokenizer, node->firstChild->sibling, "Expected a semicolon at the end of the expression.\n");
				return NULL;
			}
		}
	}

	return node;
}

Node *ParseVariableDeclarationOrExpression(Tokenizer *tokenizer) {
	Tokenizer copy = *tokenizer;
	bool isVariableDeclaration = false;

	if (ParseType(tokenizer, true, false) && TokenNext(tokenizer).type == T_IDENTIFIER) {
		Token equalsOrSemicolon = TokenNext(tokenizer);

		if (equalsOrSemicolon.type == T_EQUALS || equalsOrSemicolon.type == T_SEMICOLON) {
			isVariableDeclaration = true;
		}
	}

	if (tokenizer->error) {
		return NULL;
	}

	*tokenizer = copy;

	if (isVariableDeclaration) {
		Node *declaration = (Node *) AllocateFixed(sizeof(Node));
		declaration->type = T_DECLARE;
		declaration->firstChild = ParseType(tokenizer, false, false);
		Assert(declaration->firstChild);
		declaration->token = TokenNext(tokenizer);
		Assert(declaration->token.type == T_IDENTIFIER);
		Token equalsOrSemicolon = TokenNext(tokenizer);
		Assert(equalsOrSemicolon.type == T_EQUALS || equalsOrSemicolon.type == T_SEMICOLON);

		if (equalsOrSemicolon.type == T_EQUALS) {
			declaration->firstChild->sibling = ParseExpression(tokenizer, false, 0);
			if (!declaration->firstChild->sibling) return NULL;
			Token semicolon = TokenNext(tokenizer);

			if (semicolon.type != T_SEMICOLON) {
				PrintError2(tokenizer, declaration, "Expected a semicolon at the end of the variable declaration.\n");
				return NULL;
			}
		}

		return declaration;
	} else {
		Node *expression = ParseExpression(tokenizer, true, 0);
		if (!expression) return NULL;

		Token semicolon = TokenNext(tokenizer);

		if (semicolon.type != T_SEMICOLON) {
			PrintError2(tokenizer, expression, "Expected a semicolon at the end of the expression.\n");
			return NULL;
		}

		return expression;
	}
}

Node *ParseBlock(Tokenizer *tokenizer) {
	Node *node = (Node *) AllocateFixed(sizeof(Node));
	Node **link = &node->firstChild;
	node->type = T_BLOCK;
	node->token.line = tokenizer->line;
	node->token.module = tokenizer->module;

	while (true) {
		Token token = TokenPeek(tokenizer);

		if (token.type == T_ERROR) {
			return NULL;
		} else if (token.type == T_RIGHT_FANCY) {
			TokenNext(tokenizer);
			return node;
		} else if (token.type == T_IF) {
			Node *node = ParseIf(tokenizer);
			if (!node) return NULL;
			*link = node;
			link = &node->sibling;
		} else if (token.type == T_WHILE) {
			Node *node = (Node *) AllocateFixed(sizeof(Node));
			node->type = T_WHILE;
			node->token = TokenNext(tokenizer);
			node->firstChild = ParseExpression(tokenizer, false, 0);
			if (!node->firstChild) return NULL;
			Token token = TokenNext(tokenizer);

			if (token.type != T_LEFT_FANCY && token.type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a block or semicolon after the while condition.\n");
				return NULL;
			}

			if (token.type == T_LEFT_FANCY) {
				node->firstChild->sibling = ParseBlock(tokenizer);
				if (!node->firstChild->sibling) return NULL;
			} else {
				node->firstChild->sibling = (Node *) AllocateFixed(sizeof(Node));
				node->firstChild->sibling->type = T_BLOCK;
			}

			*link = node;
			link = &node->sibling;
		} else if (token.type == T_FOR) {
			// TODO Optional components.

			Node *node = (Node *) AllocateFixed(sizeof(Node));
			node->type = T_FOR;
			node->token = TokenNext(tokenizer);
			node->firstChild = ParseVariableDeclarationOrExpression(tokenizer);
			if (!node->firstChild) return NULL;
			node->firstChild->sibling = ParseExpression(tokenizer, false, 0);
			if (!node->firstChild->sibling) return NULL;

			Token token = TokenNext(tokenizer);

			if (token.type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a semicolon.\n");
				return NULL;
			}

			node->firstChild->sibling->sibling = ParseExpression(tokenizer, true, 0);
			if (!node->firstChild->sibling->sibling) return NULL;

			token = TokenNext(tokenizer);

			if (token.type != T_LEFT_FANCY && token.type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a block or semicolon to complete the for statement.\n");
				return NULL;
			}

			if (token.type == T_LEFT_FANCY) {
				node->firstChild->sibling->sibling->sibling = ParseBlock(tokenizer);
				if (!node->firstChild->sibling->sibling->sibling) return NULL;
			} else {
				node->firstChild->sibling->sibling->sibling = (Node *) AllocateFixed(sizeof(Node));
				node->firstChild->sibling->sibling->sibling->type = T_BLOCK;
			}

			// Make sure that the for variable has its own scope.
			Node *wrapper = (Node *) AllocateFixed(sizeof(Node));
			wrapper->type = T_BLOCK;
			wrapper->token = node->token;
			wrapper->firstChild = node;

			*link = wrapper;
			link = &wrapper->sibling;
		} else if (token.type == T_RETURN || token.type == T_ASSERT) {
			Node *node = (Node *) AllocateFixed(sizeof(Node));
			node->type = token.type;
			node->token = TokenNext(tokenizer);
			*link = node;
			link = &node->sibling;

			if (token.type == T_ASSERT || TokenPeek(tokenizer).type != T_SEMICOLON) {
				node->firstChild = ParseExpression(tokenizer, false, 0);
				if (!node->firstChild) return NULL;
			}

			Token semicolon = TokenNext(tokenizer);

			if (semicolon.type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a semicolon at the end of the statement.\n");
				return NULL;
			}
		} else if (token.type == T_LEFT_FANCY) {
			TokenNext(tokenizer);
			Node *block = ParseBlock(tokenizer);
			if (!block) return NULL;
			*link = block;
			link = &block->sibling;
		} else {
			Node *node = ParseVariableDeclarationOrExpression(tokenizer);
			if (!node) return NULL;
			*link = node;
			link = &node->sibling;
		}
	}
}

Node *ParseGlobalVariableOrFunctionDefinition(Tokenizer *tokenizer, bool allowGlobalVariables, bool parseFunctionBody) {
	Node *type = ParseType(tokenizer, false, true);

	if (!type) {
		return NULL;
	}

	Node *node = (Node *) AllocateFixed(sizeof(Node));
	node->token = TokenNext(tokenizer);

	if (node->token.type != T_IDENTIFIER) {
		if (allowGlobalVariables) {
			PrintError2(tokenizer, node, "Expected an identifier for the name of the function or global variable.\n");
		} else {
			PrintError2(tokenizer, node, "Expected an identifier for the name of the function pointer type.\n");
		}

		return NULL;
	}

	Token bracket = TokenPeek(tokenizer);

	if (bracket.type == T_ERROR) {
		return NULL;
	} else if (bracket.type == T_LEFT_ROUND) {
		TokenNext(tokenizer);
		node->type = T_FUNCTION;
		Node *functionPointerType = (Node *) AllocateFixed(sizeof(Node));
		functionPointerType->type = T_FUNCPTR;
		node->firstChild = functionPointerType;
		Node *arguments = (Node *) AllocateFixed(sizeof(Node));
		arguments->type = T_ARGUMENTS;
		functionPointerType->firstChild = arguments;
		arguments->sibling = type;
		Node **link = &arguments->firstChild;
		int argumentCount = 0;

		while (true) {
			Token token = TokenPeek(tokenizer);

			if (token.type == T_RIGHT_ROUND) {
				TokenNext(tokenizer);
				break;
			}

			if (arguments->firstChild) {
				Token comma = TokenNext(tokenizer);

				if (comma.type != T_COMMA) {
					Node n = { .token = comma };
					PrintError2(tokenizer, &n, "Expected a comma to separate function arguments.\n");
					return NULL;
				}
			}

			Node *argument = (Node *) AllocateFixed(sizeof(Node));
			argument->type = T_ARGUMENT;
			argument->firstChild = ParseType(tokenizer, false, false);
			if (!argument->firstChild) return NULL;
			argument->token = TokenNext(tokenizer);
			*link = argument;
			link = &argument->sibling;
			argumentCount++;

#define FUNCTION_MAX_ARGUMENTS (20)
			if (argumentCount > FUNCTION_MAX_ARGUMENTS) {
				PrintError2(tokenizer, argument, "Functions cannot have more than %d arguments.\n", FUNCTION_MAX_ARGUMENTS);
				return NULL;
			}

			if (argument->token.type != T_IDENTIFIER) {
				PrintError2(tokenizer, argument, "Expected an identifier for the name of the function argument.\n");
				return NULL;
			}
		}

		if (parseFunctionBody) {
			Token token = TokenNext(tokenizer);

			if (token.type == T_LEFT_FANCY) {
				Node *body = (Node *) AllocateFixed(sizeof(Node));
				body->type = T_FUNCBODY;
				functionPointerType->sibling = body;
				body->firstChild = ParseBlock(tokenizer);

				if (!body->firstChild) {
					return NULL;
				}
			} else if (token.type == T_EXTCALL) {
				Token semicolon = TokenNext(tokenizer);

				if (semicolon.type != T_SEMICOLON) {
					PrintError(tokenizer, "Expected a semicolon after 'extcall'.\n");
					return NULL;
				}

				node->isExternalCall = true;
			} else {
				Node n = { .token = token };
				PrintError2(tokenizer, &n, "Expected a '{' to start the function body.\n");
				return NULL;
			}
		}
	} else if (allowGlobalVariables) {
		Token semicolon = TokenNext(tokenizer);

		if (semicolon.type == T_PERSIST) {
			node->isPersistentVariable = true;
			semicolon = TokenNext(tokenizer);
		}

		if (semicolon.type == T_OPTION) {
			node->isOptionVariable = true;
			semicolon = TokenNext(tokenizer);
		}

		if (semicolon.type != T_SEMICOLON) {
			PrintError(tokenizer, "Expected a semicolon after the global variable definition.\n");
			return NULL;
		}

		node->type = T_DECLARE;
		node->firstChild = type;
	} else {
		PrintError(tokenizer, "Expected a '(' to start the argument list.\n");
		return NULL;
	}

	return node;
}

Node *ParseRoot(Tokenizer *tokenizer) {
	Node *root = (Node *) AllocateFixed(sizeof(Node));
	root->type = T_ROOT;
	Node **link = &root->firstChild;

	if (!tokenizer->isBaseModule) {
		Node *node = (Node *) AllocateFixed(sizeof(Node));
		node->type = T_IMPORT;
		node->token.type = T_INLINE;
		node->token.text = "#inline";
		node->token.textBytes = 7;
		node->firstChild = (Node *) AllocateFixed(sizeof(Node));
		node->firstChild->type = T_IMPORT_PATH;
		node->firstChild->token.type = T_STRING_LITERAL;
		node->firstChild->token.text = "__base_module__";
		node->firstChild->token.textBytes = 15;
		*link = node;
		link = &node->sibling;
	}

	while (true) {
		Token token = TokenPeek(tokenizer);

		if (token.type == T_ERROR) {
			return NULL;
		} else if (token.type == T_EOF) {
			return root;
		} else if (token.type == T_FUNCTYPE) {
			TokenNext(tokenizer);
			Node *node = ParseGlobalVariableOrFunctionDefinition(tokenizer, false, false);
			if (!node) return NULL;
			node->type = T_FUNCTYPE;
			*link = node;
			link = &node->sibling;

			Token semicolon = TokenNext(tokenizer);

			if (semicolon.type != T_SEMICOLON) {
				PrintError2(tokenizer, node->firstChild->sibling, "Expected a semicolon after the argument list.\n");
				return NULL;
			}
		} else if (token.type == T_STRUCT) {
			TokenNext(tokenizer);
			Node *node = (Node *) AllocateFixed(sizeof(Node));
			node->type = T_STRUCT;
			node->token = TokenNext(tokenizer);
			*link = node;
			link = &node->sibling;

			if (node->token.type != T_IDENTIFIER) {
				PrintError2(tokenizer, node, "Expected the name of the struct.\n");
				return NULL;
			}

			if (TokenNext(tokenizer).type != T_LEFT_FANCY) {
				PrintError2(tokenizer, node, "Expected a '{' for the struct contents after the name.\n");
				return NULL;
			}

			Node **fieldLink = &node->firstChild;

			while (true) {
				Token peek = TokenPeek(tokenizer);
				if (peek.type == T_ERROR) return NULL;
				if (peek.type == T_RIGHT_FANCY) break;
				Node *type = ParseType(tokenizer, false, true);
				if (!type) return NULL;
				Node *field = (Node *) AllocateFixed(sizeof(Node));
				field->token = TokenNext(tokenizer);
				field->type = T_DECLARE;
				field->firstChild = type;
				*fieldLink = field;
				fieldLink = &field->sibling;

				if (field->token.type != T_IDENTIFIER) {
					PrintError2(tokenizer, field, "Expected an identifier for the field name.\n");
					return NULL;
				}

				if (TokenNext(tokenizer).type != T_SEMICOLON) {
					PrintError2(tokenizer, field, "Expected a semicolon after the field name.\n");
					return NULL;
				}
			}

			TokenNext(tokenizer);

			if (TokenNext(tokenizer).type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a semicolon after the struct body.\n");
				return NULL;
			}
		} else if (token.type == T_IMPORT) {
			Node *node = (Node *) AllocateFixed(sizeof(Node));
			node->type = T_IMPORT;
			TokenNext(tokenizer);
			node->firstChild = ParseExpression(tokenizer, false, 0);
			if (!node->firstChild) return NULL;
			node->token = TokenNext(tokenizer);

			if (node->firstChild->type != T_STRING_LITERAL) {
				PrintError2(tokenizer, node, "The path to the script file to import must be a string literal.\n");
				return NULL;
			} else if (node->token.type != T_IDENTIFIER && node->token.type != T_INLINE) {
				PrintError2(tokenizer, node, "Expected an identifier for the name to import the module as.\n");
				return NULL;
			}

			node->firstChild->type = T_IMPORT_PATH;
			*link = node;
			link = &node->sibling;

			if (TokenNext(tokenizer).type != T_SEMICOLON) {
				PrintError2(tokenizer, node, "Expected a semicolon after the import statement.\n");
				return NULL;
			}
		} else {
			Node *node = ParseGlobalVariableOrFunctionDefinition(tokenizer, true, true);
			if (!node) return NULL;
			*link = node;
			link = &node->sibling;
		}
	}
}

// --------------------------------- Scope management.

bool ScopeIsVariableType(Node *node) {
	return node->type == T_DECLARE || node->type == T_FUNCTION || node->type == T_ARGUMENT;
}

intptr_t ScopeLookupIndex(Node *node, Scope *scope, bool maybe, bool real /* if false, the variable index is returned */) {
	uintptr_t j = 0;

	for (uintptr_t i = 0; i < scope->entryCount; i++) {
		if (scope->entries[i]->token.textBytes == node->token.textBytes
				&& 0 == MemoryCompare(scope->entries[i]->token.text, node->token.text, node->token.textBytes)) {
			if (!ScopeIsVariableType(scope->entries[i]) && !real) {
				break;
			}

			return j;
		}

		if (ScopeIsVariableType(scope->entries[i]) || real) {
			j++;
		}
	}

	if (!maybe) {
		Assert(false);
	}

	return -1;
}

Node *ScopeLookup(Tokenizer *tokenizer, Node *node, bool maybe) {
	Node *ancestor = node;
	Scope *scope = NULL;

	while (ancestor) {
		if (ancestor->scope != scope) {
			scope = ancestor->scope;

			for (uintptr_t i = 0; i < scope->entryCount; i++) {
				if (scope->entries[i]->token.textBytes == node->token.textBytes
						&& 0 == MemoryCompare(scope->entries[i]->token.text, node->token.text, node->token.textBytes)) {
					if (node->referencesRootScope && scope->entries[i]->parent->type != T_ROOT) {
						PrintError2(tokenizer, node, "The identifier '%.*s' is used before it is declared in this scope.\n", 
								node->token.textBytes, node->token.text);
						return NULL;
					}

					return scope->entries[i];
				}
			}
		}

		ancestor = ancestor->parent;
	}

	if (!maybe) {
		PrintError2(tokenizer, node, "Could not find identifier '%.*s' inside its scope.\n", node->token.textBytes, node->token.text);
	}

	return NULL;
}

bool ScopeCheckNotAlreadyUsed(Tokenizer *tokenizer, Node *node) {
	Node *ancestor = node;
	Scope *scope = NULL;

	while (ancestor) {
		if (ancestor->scope != scope) {
			scope = ancestor->scope;

			for (uintptr_t i = 0; i < scope->entryCount; i++) {
				if (scope->entries[i]->token.textBytes == node->token.textBytes
						&& 0 == MemoryCompare(scope->entries[i]->token.text, node->token.text, node->token.textBytes)
						&& (!scope->isRoot || node->scope == scope)) {
					PrintError2(tokenizer, node, "The identifier '%.*s' was already used in this scope.\n", 
							node->token.textBytes, node->token.text);

					if (scope->entries[i]->type == T_INLINE) {
						if (scope->entries[i]->importData->pathBytes == 15 
								&& 0 == MemoryCompare(scope->entries[i]->importData->path, "__base_module__", scope->entries[i]->importData->pathBytes)) {
							PrintDebug("It was declared in base library module.\n", 
									scope->entries[i]->importData->path);
						} else {
							PrintDebug("It was imported inline from the module '%s'.\n", 
									scope->entries[i]->importData->path);
						}
					}

					return false;
				}
			}
		}

		ancestor = ancestor->parent;
	}

	return true;
}

bool ScopeAddEntry(Tokenizer *tokenizer, Scope *scope, Node *node) {
	if (node->type == T_IMPORT && node->token.type == T_INLINE) {
		return true;
	}

	node->scope = scope;

	if (scope->entryCount == scope->entriesAllocated) {
		scope->entriesAllocated = scope->entriesAllocated ? scope->entriesAllocated * 2 : 4;
		scope->entries = (Node **) AllocateResize(scope->entries, sizeof(Node *) * scope->entriesAllocated);
	}

	if (!ScopeCheckNotAlreadyUsed(tokenizer, node)) {
		return false;
	}

	scope->entries[scope->entryCount++] = node;

	if (ScopeIsVariableType(node)) {
		scope->variableEntryCount++;
	}

	// Set this here before type checking occurs, 
	// so that all the declarations in the scope already have their expression type set.
	node->expressionType = node->firstChild;

	return true;
}

void ASTFreeScopes(Node *node) {
	if (node->scope) {
		node->scope->entries = AllocateResize(node->scope->entries, 0);

		Node *child = node->firstChild;

		while (child) {
			ASTFreeScopes(child);
			child = child->sibling;
		}
	}
}

bool ASTSetScopes(Tokenizer *tokenizer, ExecutionContext *context, Node *node, Scope *scope) {
	Node *child = node->firstChild;

	while (child) {
		child->parent = node;
		child = child->sibling;
	}

	if (node->type == T_ROOT || node->type == T_BLOCK || node->type == T_FUNCBODY) {
		scope = node->scope = (Scope *) AllocateFixed(sizeof(Scope));
		scope->isRoot = node->type == T_ROOT;
	} else {
		node->scope = scope;
	}

	if (node->type == T_FUNCBODY) {
		Node *argument = node->parent->firstChild->firstChild->firstChild;

		while (argument) {
			if (!ScopeAddEntry(tokenizer, scope, argument)) {
				return false;
			}
			
			argument = argument->sibling;
		}
	}

	if (node->type == T_VARIABLE) {
		Node *referenced = ScopeLookup(tokenizer, node, true);

		if (!referenced || referenced->parent->type == T_ROOT) {
			// (If the lookup fails, then it must be a forward declaration, which is only allowed at the root scope level.)
			node->referencesRootScope = true;
		}
	}

	if (node->type != T_STRUCT) {
		child = node->firstChild;

		while (child) {
			if (!ASTSetScopes(tokenizer, context, child, scope)) {
				return false;
			}

			child = child->sibling;
		}
	}

	if (node->type == T_DECLARE || node->type == T_FUNCTION || node->type == T_FUNCTYPE 
			|| node->type == T_STRUCT || node->type == T_IMPORT) {
		if (!ScopeAddEntry(tokenizer, scope, node)) {
			return false;
		}
	}

	if (node->type == T_IMPORT) {
		ImportData *alreadyImportedModule = importedModules;

		while (alreadyImportedModule) {
			if (alreadyImportedModule->pathBytes == node->firstChild->token.textBytes
					&& 0 == MemoryCompare(alreadyImportedModule->path, node->firstChild->token.text, alreadyImportedModule->pathBytes)) {
				break;
			}

			alreadyImportedModule = alreadyImportedModule->nextImport;
		}

		if (alreadyImportedModule) {
#if 0
			PrintError2(tokenizer, node, "The script at path '%.*s' has already been imported as a module.\n",
					node->firstChild->token.textBytes, node->firstChild->token.text);
			return false;
#else
			node->importData = alreadyImportedModule;
#endif
		} else {
			char *path = (char *) AllocateFixed(node->firstChild->token.textBytes + 1);
			MemoryCopy(path, node->firstChild->token.text, node->firstChild->token.textBytes);
			path[node->firstChild->token.textBytes] = 0;

			Tokenizer t = { 0 };
			void *fileData;

			if (node->firstChild->token.textBytes == 15 
					&& 0 == MemoryCompare(node->firstChild->token.text, "__base_module__", node->firstChild->token.textBytes)) {
				fileData = BASE_MODULE_SOURCE;
				t.inputBytes = sizeof(BASE_MODULE_SOURCE) - 1;
				t.isBaseModule = true;
			} else {
				fileData = FileLoad(path, &t.inputBytes);
			}

			if (!fileData) {
				PrintError2(tokenizer, node, "The script at path '%.*s' could not be loaded.\n",
						node->firstChild->token.textBytes, node->firstChild->token.text);
				return false;
			}

			node->importData = AllocateFixed(sizeof(ImportData));
			node->importData->fileDataBytes = t.inputBytes;
			node->importData->fileData = fileData;
			node->importData->path = path;
			node->importData->pathBytes = node->firstChild->token.textBytes;
			node->importData->parentImport = tokenizer->module;

			ImportData *parentImport = tokenizer->module;

			while (parentImport) {
				if (parentImport->pathBytes == node->firstChild->token.textBytes
						&& 0 == MemoryCompare(parentImport->path, node->firstChild->token.text, parentImport->pathBytes)) {
					PrintError3("There is a cyclic import dependency.\n");
					ImportData *data = node->importData;

					while (data->parentImport) {
						PrintDebug("- '%s' is imported by '%s'\n", data->path, data->parentImport->path);
						data = data->parentImport;
					}

					return false;
				}

				parentImport = parentImport->parentImport;
			}

			t.module = node->importData;
			t.input = fileData;
			t.line = 1;

			if (!ScriptLoad(t, context, node->importData)) {
				return false;
			}
		}

		if (node->token.type == T_INLINE) {
			uintptr_t j = 0;

			for (uintptr_t i = 0; i < node->importData->rootNode->scope->entryCount; i++) {
				if (node->importData->rootNode->scope->entries[i]->type == T_INLINE) {
					continue;
				}

				Node *inlineNode = (Node *) AllocateFixed(sizeof(Node));
				inlineNode->token = node->importData->rootNode->scope->entries[i]->token;
				inlineNode->type = T_INLINE;
				inlineNode->parent = node->parent;
				inlineNode->firstChild = node->importData->rootNode->scope->entries[i]->expressionType;
				inlineNode->importData = node->importData;

				if (ScopeIsVariableType(node->importData->rootNode->scope->entries[i])) {
					inlineNode->inlineImportVariableIndex = j++;
				} else {
					inlineNode->inlineImportVariableIndex = -1;
				}

				if (!ScopeAddEntry(tokenizer, scope, inlineNode)) {
					return false;
				}
			}
		}
	}

	return true;
}

// --------------------------------- Type checking.

bool ASTMatching(Node *left, Node *right) {
	if (left && left->resolveAs) left = left->resolveAs;
	if (right && right->resolveAs) right = right->resolveAs;

	if (!left && !right) {
		return true;
	} else if (!left || !right) {
		return false;
	} else if (left->type == T_NULL && right->type == T_STRUCT) {
		return true;
	} else if (right->type == T_NULL && left->type == T_STRUCT) {
		return true;
	} else if (left->type != right->type) {
		return false;
	} else if ((left->type == T_IDENTIFIER || left->type == T_STRUCT) 
			&& (left->token.textBytes != right->token.textBytes 
				|| MemoryCompare(left->token.text, right->token.text, right->token.textBytes))) {
		return false;
	} else {
		Node *childLeft = left->firstChild;
		Node *childRight = right->firstChild;

		while (true) {
			if (!childLeft && !childRight) {
				return true;
			} else if (!childLeft || !childRight) {
				return false;
			} else if (!ASTMatching(childLeft, childRight)) {
				return false;
			} else {
				childLeft = childLeft->sibling;
				childRight = childRight->sibling;
			}
		}
	}
}

bool ASTIsManagedType(Node *node) {
	return node->type == T_STR || node->type == T_LIST || (node->resolveAs && node->resolveAs->type == T_STRUCT);
}

bool ASTLookupTypeIdentifiers(Tokenizer *tokenizer, Node *node) {
	Node *child = node->firstChild;

	while (child) {
		if (!ASTLookupTypeIdentifiers(tokenizer, child)) return false;
		child = child->sibling;
	}

	if (node->type == T_DECLARE || node->type == T_ARGUMENT || node->type == T_NEW) {
		Node *type = node->firstChild;

		if (type->type == T_IDENTIFIER) {
			Node *lookup = ScopeLookup(tokenizer, type, false);

			if (lookup->type == T_FUNCTYPE) {
				node->expressionType->resolveAs = lookup->firstChild;
			} else if (lookup->type == T_STRUCT) {
				node->expressionType->resolveAs = lookup;
			} else {
				PrintError2(tokenizer, node, "The identifier did not resolve to a type.\n");
				return false;
			}
		}
	}

	return true;
}

bool ASTSetTypes(Tokenizer *tokenizer, Node *node) {
	Node *child = node->firstChild;

	while (child) {
		if (!ASTSetTypes(tokenizer, child)) return false;
		child->parent = node;
		child = child->sibling;
	}

	if (node->type == T_ROOT || node->type == T_BLOCK
			|| node->type == T_INT || node->type == T_FLOAT || node->type == T_STR || node->type == T_LIST
			|| node->type == T_BOOL || node->type == T_VOID || node->type == T_IDENTIFIER
			|| node->type == T_ARGUMENTS || node->type == T_ARGUMENT
			|| node->type == T_STRUCT || node->type == T_FUNCTYPE || node->type == T_IMPORT || node->type == T_IMPORT_PATH
			|| node->type == T_FUNCPTR || node->type == T_FUNCBODY || node->type == T_FUNCTION) {
	} else if (node->type == T_NUMERIC_LITERAL) {
		size_t dotCount = 0;

		for (uintptr_t i = 0; i < node->token.textBytes; i++) {
			if (node->token.text[i] == '.') {
				dotCount++;
			}
		}

		if (dotCount == 0) {
			node->expressionType = &globalExpressionTypeInt;
		} else if (dotCount == 1) {
			node->expressionType = &globalExpressionTypeFloat;
		} else {
			PrintError2(tokenizer, node, "Invalid number. There should either be one decimal place (for a float), or none (for an integer).\n");
			return false;
		}
	} else if (node->type == T_TRUE || node->type == T_FALSE) {
		node->expressionType = &globalExpressionTypeBool;
	} else if (node->type == T_NULL) {
		node->expressionType = node;
	} else if (node->type == T_STRING_LITERAL) {
		node->expressionType = &globalExpressionTypeStr;
	} else if (node->type == T_VARIABLE) {
		Node *lookup = ScopeLookup(tokenizer, node, false);
		if (!lookup) return false;
		node->expressionType = lookup->expressionType;
	} else if (node->type == T_STR_INTERPOLATE) {
		Node *left = node->firstChild;
		Node *expression = node->firstChild->sibling;
		Node *right = node->firstChild->sibling->sibling;
		Assert(left->type == T_STRING_LITERAL || left->type == T_STR_INTERPOLATE);
		Assert(right->type == T_STRING_LITERAL);
		Assert(left->expressionType->type == T_STR);
		Assert(right->expressionType->type == T_STR);
		node->expressionType = &globalExpressionTypeStr;

		// TODO Converting more types to strings.

		if (!ASTMatching(expression->expressionType, &globalExpressionTypeInt)
				&& !ASTMatching(expression->expressionType, &globalExpressionTypeStr)
				&& !ASTMatching(expression->expressionType, &globalExpressionTypeFloat)
				&& !ASTMatching(expression->expressionType, &globalExpressionTypeBool)) {
			PrintError2(tokenizer, expression, "The expression cannot be converted to a string.\n");
			return false;
		}
	} else if (node->type == T_ADD || node->type == T_MINUS || node->type == T_ASTERISK || node->type == T_SLASH
			|| node->type == T_GREATER_THAN || node->type == T_LESS_THAN || node->type == T_LT_OR_EQUAL || node->type == T_GT_OR_EQUAL
			|| node->type == T_DOUBLE_EQUALS || node->type == T_NOT_EQUALS || node->type == T_LOGICAL_AND || node->type == T_LOGICAL_OR) {
		if (!ASTMatching(node->firstChild->expressionType, node->firstChild->sibling->expressionType)) {
			PrintError2(tokenizer, node, "The expression on the left and right side of a binary operator must have the same type.\n");
			return false;
		}

		if (node->type == T_ADD) {
			if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeInt)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeFloat)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeStr)) {
				PrintError2(tokenizer, node, "The add operator expects integers, floats or strings.\n");
				return false;
			}
		} else if (node->type == T_LOGICAL_AND || node->type == T_LOGICAL_OR) {
			if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeBool)) {
				PrintError2(tokenizer, node, "This operator expects boolean expressions.\n");
				return false;
			}
		} else if (node->type == T_DOUBLE_EQUALS || node->type == T_NOT_EQUALS) {
			if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeInt)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeFloat)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeStr)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeBool)) {
				PrintError2(tokenizer, node, "This operator expects either integers, floats, strings or booleans.\n");
				return false;
			}
		} else {
			if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeInt)
					&& !ASTMatching(node->firstChild->expressionType, &globalExpressionTypeFloat)) {
				PrintError2(tokenizer, node, "This operator expects either integers or floats.\n");
				return false;
			}
		}

		if (node->type == T_GREATER_THAN || node->type == T_LESS_THAN || node->type == T_LT_OR_EQUAL || node->type == T_GT_OR_EQUAL
				|| node->type == T_DOUBLE_EQUALS || node->type == T_NOT_EQUALS) {
			node->expressionType = &globalExpressionTypeBool;
		} else {
			node->expressionType = node->firstChild->expressionType;
		}
	} else if (node->type == T_DECLARE) {
		if (node->firstChild->sibling && !ASTMatching(node->firstChild, node->firstChild->sibling->expressionType)) {
			PrintError2(tokenizer, node, "The type of the variable being assigned does not match the expression.\n");
			return false;
		}
	} else if (node->type == T_EQUALS) {
		if (!ASTMatching(node->firstChild->expressionType, node->firstChild->sibling->expressionType)) {
			PrintError2(tokenizer, node, "The type of the variable being assigned does not match the expression.\n");
			return false;
		}
	} else if (node->type == T_CALL) {
		Node *functionPointer = node->firstChild;
		Node *expressionType = functionPointer->expressionType 
			? (functionPointer->expressionType->resolveAs ? functionPointer->expressionType->resolveAs : functionPointer->expressionType) : NULL;

		if (!expressionType || expressionType->type != T_FUNCPTR) {
			PrintError2(tokenizer, functionPointer, "The expression being called is not a function.\n");
			return false;
		}

		node->expressionType = expressionType->firstChild->sibling;
		Node *match = expressionType->firstChild->firstChild;
		Node *argument = node->firstChild->sibling->firstChild;
		size_t index = 1;

		while (true) {
			if (!argument && !match) {
				break;
			} else if (!argument || !match) {
				PrintError2(tokenizer, node, "The function has a different number of arguments to this.\n");
				return false;
			} else {
				if (!ASTMatching(argument->expressionType, match->firstChild)) {
					PrintError2(tokenizer, node, "The types for argument %d do not match.\n", index);
					return false;
				}

				match = match->sibling;
				argument = argument->sibling;
				index++;
			}
		}
	} else if (node->type == T_ASSERT) {
		if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeBool)) {
			PrintError2(tokenizer, node, "The asserted expression must evaluate to a boolean.\n");
			return false;
		}
	} else if (node->type == T_RETURN) {
		Node *expressionType = node->firstChild ? node->firstChild->expressionType : &globalExpressionTypeVoid;

		Node *function = node->parent;

		while (function->type != T_FUNCTION) {
			function = function->parent;
		}

		Node *returnType = function->firstChild->firstChild->sibling;

		if (node->firstChild && ASTMatching(returnType, &globalExpressionTypeVoid)) {
			PrintError2(tokenizer, node, "The function does not return a value ('void'), but the return statement has a return value.\n");
			return false;
		}

		if (!ASTMatching(expressionType, returnType)) {
			PrintError2(tokenizer, node, "The type of the expression does not match the declared return type of the function.\n");
			return false;
		}
	} else if (node->type == T_IF || node->type == T_WHILE) {
		if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeBool)) {
			PrintError2(tokenizer, node, "The expression used for the condition must evaluate to a boolean.\n");
			return false;
		}
	} else if (node->type == T_FOR) {
		if (!ASTMatching(node->firstChild->sibling->expressionType, &globalExpressionTypeBool)) {
			PrintError2(tokenizer, node, "The expression used for the condition must evaluate to a boolean.\n");
			return false;
		}
	} else if (node->type == T_INDEX) {
		if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeStr)
				&& node->firstChild->expressionType->type != T_LIST) {
			PrintError2(tokenizer, node, "The expression being indexed must be a string or list.\n");
			return false;
		}

		if (!ASTMatching(node->firstChild->sibling->expressionType, &globalExpressionTypeInt)) {
			PrintError2(tokenizer, node, "The index must be a integer.\n");
			return false;
		}

		if (ASTMatching(node->firstChild->expressionType, &globalExpressionTypeStr)) {
			node->expressionType = &globalExpressionTypeStr;
		} else {
			node->expressionType = node->firstChild->expressionType->firstChild;
		}
	} else if (node->type == T_NEW) {
		if ((!node->firstChild->resolveAs || node->firstChild->resolveAs->type != T_STRUCT)
				&& node->firstChild->type != T_LIST) {
			PrintError2(tokenizer, node, "This type is not a struct or list. 'new' is used to create new instances of structs or lists.\n");
			return false;
		}
	} else if (node->type == T_DOT) {
		bool isStruct = node->firstChild->expressionType->resolveAs && node->firstChild->expressionType->resolveAs->type == T_STRUCT;

		if (!isStruct && node->firstChild->expressionType->type != T_IMPORT_PATH) {
			PrintError2(tokenizer, node, "This expression is not a struct or an imported module. "
					"You cannot use the '.' operator on it.\n");
			return false;
		}

		if (isStruct) {
			Node *structure = node->firstChild->expressionType->resolveAs;
			Node *field = structure->firstChild;

			while (field) {
				if (field->token.textBytes == node->token.textBytes && 
						0 == MemoryCompare(field->token.text, node->token.text, node->token.textBytes)) {
					break;
				}

				field = field->sibling;
			}

			if (!field) {
				PrintError2(tokenizer, node, "The field '%.*s' is not in the struct '%.*s'.\n",
						node->token.textBytes, node->token.text, structure->token.textBytes, structure->token.text);
				return false;
			}

			node->expressionType = field->firstChild;
		} else {
			ImportData *importData = node->firstChild->expressionType->parent->importData;
			intptr_t index = ScopeLookupIndex(node, importData->rootNode->scope, true, true);

			if (index == -1) {
				PrintError2(tokenizer, node, "The variable or function '%.*s' is not in the imported module '%s'.\n",
						node->token.textBytes, node->token.text, importData->path);
				return false;
			}

			node->expressionType = importData->rootNode->scope->entries[index]->expressionType;
		}
	} else if (node->type == T_COLON) {
		bool isList = node->firstChild->expressionType->type == T_LIST;
		bool isStr = node->firstChild->expressionType->type == T_STR;

		if (!isList && !isStr) {
			PrintError2(tokenizer, node, "This type does not have any ':' operations.\n");
			return false;
		}

		Token token = node->token;
		Node *arguments[2] = { 0 };
		bool returnsItem = false, returnsInt = false;
		uint8_t op;

		if (isList && KEYWORD("resize")) arguments[0] = &globalExpressionTypeInt, op = T_OP_RESIZE;
		else if (isList && KEYWORD("add")) arguments[0] = node->firstChild->expressionType->firstChild, op = T_OP_ADD;
		else if (isList && KEYWORD("insert")) arguments[0] = node->firstChild->expressionType->firstChild, arguments[1] = &globalExpressionTypeInt, op = T_OP_INSERT;
		else if (isList && KEYWORD("insert_many")) arguments[0] = &globalExpressionTypeInt, arguments[1] = &globalExpressionTypeInt, op = T_OP_INSERT_MANY;
		else if (isList && KEYWORD("delete")) arguments[0] = &globalExpressionTypeInt, op = T_OP_DELETE;
		else if (isList && KEYWORD("delete_many")) arguments[0] = &globalExpressionTypeInt, arguments[1] = &globalExpressionTypeInt, op = T_OP_DELETE_MANY;
		else if (isList && KEYWORD("delete_last")) op = T_OP_DELETE_LAST;
		else if (isList && KEYWORD("delete_all")) op = T_OP_DELETE_ALL;
		else if (isList && KEYWORD("first")) returnsItem = true, op = T_OP_FIRST;
		else if (isList && KEYWORD("last")) returnsItem = true, op = T_OP_LAST;
		else if (KEYWORD("len")) returnsInt = true, op = T_OP_LEN;
		else {
			PrintError2(tokenizer, node, "This type does not have an operation called '%.*s'.\n", token.textBytes, token.text);
			return false;
		}

		Node *argument1 = node->firstChild->sibling->firstChild;
		Node *argument2 = argument1 ? argument1->sibling : NULL;
		Node *argument3 = argument2 ? argument2->sibling : NULL;

		if (argument3 || (argument2 && !arguments[1]) || (argument1 && !arguments[0])
				|| (!argument2 && arguments[1]) || (!argument1 && arguments[0])) {
			PrintError2(tokenizer, node, "Incorrect number of arguments for the operation '%.*s'.\n", token.textBytes, token.text);
			return false;
		}

		if (argument1 && !ASTMatching(argument1->expressionType, arguments[0])) {
			PrintError2(tokenizer, node, "Incorrect first argument type for the operation '%.*s'.\n", token.textBytes, token.text);
			return false;
		}

		if (argument2 && !ASTMatching(argument1->expressionType, arguments[1])) {
			PrintError2(tokenizer, node, "Incorrect second argument type for the operation '%.*s'.\n", token.textBytes, token.text);
			return false;
		}

		node->expressionType = returnsItem ? node->firstChild->expressionType->firstChild : returnsInt ? &globalExpressionTypeInt : NULL;
		node->operationType = op;
	} else if (node->type == T_LOGICAL_NOT) {
		if (!ASTMatching(node->firstChild->expressionType, &globalExpressionTypeBool)) {
			PrintError2(tokenizer, node, "Expected a bool for the logical not '!' operator.\n");
			return false;
		}

		node->expressionType = &globalExpressionTypeBool;
	} else {
		PrintDebug("ASTSetTypes %d\n", node->type);
		Assert(false);
	}

	return true;
}

bool ASTCheckForReturnStatements(Tokenizer *tokenizer, Node *node) {
	if (node->type == T_ROOT) {
		Node *child = node->firstChild;

		while (child) {
			if (!ASTCheckForReturnStatements(tokenizer, child)) return false;
			child->parent = node;
			child = child->sibling;
		}
	} else if (node->type == T_FUNCTION) {
		if (node->firstChild->sibling && node->firstChild->firstChild->sibling
				&& node->firstChild->firstChild->sibling->type != T_VOID) {
			Assert(node->firstChild->sibling->type == T_FUNCBODY);
			return ASTCheckForReturnStatements(tokenizer, node->firstChild->sibling);
		}
	} else if (node->type == T_BLOCK || node->type == T_FUNCBODY) {
		Node *lastStatement = node->firstChild;

		while (lastStatement && lastStatement->sibling) {
			lastStatement = lastStatement->sibling;
		}

		if (lastStatement && lastStatement->type == T_RETURN) {
			return true;
		} else if (lastStatement && (lastStatement->type == T_IF || lastStatement->type == T_BLOCK)) {
			return ASTCheckForReturnStatements(tokenizer, lastStatement);
		} else {
			PrintError2(tokenizer, node, "This block needs to end with a return statement.\n");
			return false;
		}
	} else if (node->type == T_IF) {
		if (!node->firstChild->sibling->sibling) {
			PrintError2(tokenizer, node, "This function returns a value, so this if statement needs an else block which ends with a return statement.\n");
			return false;
		}

		return ASTCheckForReturnStatements(tokenizer, node->firstChild->sibling)
			&& ASTCheckForReturnStatements(tokenizer, node->firstChild->sibling->sibling);
	}

	return true;
}

// --------------------------------- Code generation.

void FunctionBuilderAppend(FunctionBuilder *builder, const void *buffer, size_t bytes) {
	if (builder->dataBytes + bytes > builder->dataAllocated) {
		builder->dataAllocated = 2 * builder->dataAllocated + bytes;
		builder->data = (uint8_t *) AllocateResize(builder->data, builder->dataAllocated);
	}

	for (uintptr_t i = 0; i < bytes; i++) {
		builder->data[builder->dataBytes + i] = ((const uint8_t *) buffer)[i];
	}

	builder->dataBytes += bytes;
}

void FunctionBuilderAddLineNumber(FunctionBuilder *builder, Node *node) {
	if (builder->lineNumberCount == builder->lineNumbersAllocated) {
		builder->lineNumbersAllocated = 2 * builder->lineNumbersAllocated + 4;
		builder->lineNumbers = (LineNumber *) AllocateResize(builder->lineNumbers, builder->lineNumbersAllocated * sizeof(LineNumber));
	}

	Node *ancestor = node;

	while (ancestor) {
		if (ancestor->type == T_FUNCTION) {
			builder->lineNumbers[builder->lineNumberCount].function = &ancestor->token;
		}

		ancestor = ancestor->parent;
	}

	builder->lineNumbers[builder->lineNumberCount].importData = builder->importData;
	builder->lineNumbers[builder->lineNumberCount].instructionPointer = builder->dataBytes;
	builder->lineNumbers[builder->lineNumberCount].lineNumber = node->token.line;
	builder->lineNumberCount++;
}

bool FunctionBuilderVariable(Tokenizer *tokenizer, FunctionBuilder *builder, Node *node, bool forAssignment) {
	Node *ancestor = node;
	Scope *scope = NULL;
	int32_t index = -1;
	Scope *rootScope = NULL;
	uintptr_t globalVariableOffset = builder->globalVariableOffset;
	bool inlineImport = false;

	while (ancestor) {
		if (ancestor->scope != scope) {
			scope = ancestor->scope;

			if (scope->isRoot) {
				rootScope = scope;
			}

			if (index != -1) {
				index += scope->variableEntryCount;
			}

			uintptr_t j = 0;

			for (uintptr_t i = 0; i < scope->entryCount; i++) {
				if (scope->entries[i]->token.textBytes == node->token.textBytes
						&& 0 == MemoryCompare(scope->entries[i]->token.text, node->token.text, node->token.textBytes)
						&& index == -1) {
					index = j;
					builder->isPersistentVariable = scope->entries[i]->isPersistentVariable;

					if (scope->entries[i]->type == T_INLINE) {
						index = scope->entries[i]->inlineImportVariableIndex;
						Assert(index != -1);
						globalVariableOffset = scope->entries[i]->importData->globalVariableOffset;
						inlineImport = true;
					}

					if (scope->entries[i]->type != T_DECLARE && forAssignment) {
						PrintError2(tokenizer, node, "A value cannot be assigned to this. "
								"Try putting a variable name here.\n");
						return false;
					}
				}

				if (ScopeIsVariableType(scope->entries[i])) {
					j++;
				}
			}
		}

		ancestor = ancestor->parent;
	}

	if (index >= (int32_t) rootScope->variableEntryCount && !inlineImport) {
		index = rootScope->variableEntryCount - index - 1;
	} else {
		index += globalVariableOffset;
	}

	FunctionBuilderAddLineNumber(builder, node);

	if (forAssignment) {
		builder->scopeIndex = index;
		builder->isDotAssignment = false;
		builder->isListAssignment = false;
	} else {
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		FunctionBuilderAppend(builder, &index, sizeof(index));
	}

	return true;
}

bool FunctionBuilderRecurse(Tokenizer *tokenizer, Node *node, FunctionBuilder *builder, bool forAssignment) {
	if (forAssignment) {
		if (node->type == T_VARIABLE || node->type == T_DOT || node->type == T_INDEX) {
			// Supported.
		} else {
			PrintError2(tokenizer, node, "A value cannot be assigned to this expression. Try putting a variable name here.\n");
			return false;
		}
	}

	if (node->type == T_FUNCBODY || node->type == T_BLOCK) {
		if (node->scope->variableEntryCount > 10000) {
			PrintError2(tokenizer, node, "There are too many variables in this scope (the maximum is 10000).\n");
			return false;
		}

		uint16_t entryCount = node->scope->variableEntryCount;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		FunctionBuilderAppend(builder, &entryCount, sizeof(entryCount));

		for (uintptr_t i = 0; i < node->scope->entryCount; i++) {
			Node *entry = node->scope->entries[i];

			if (ScopeIsVariableType(entry)) {
				bool isManaged = ASTIsManagedType(entry->expressionType);
				FunctionBuilderAppend(builder, &isManaged, sizeof(isManaged));
			}
		}
	} else if (node->type == T_EQUALS || node->type == T_DECLARE) {
		if (node->firstChild->sibling) {
			if (!FunctionBuilderRecurse(tokenizer, node->firstChild->sibling, builder, false)) return false;
			builder->isPersistentVariable = false;

			if (node->type == T_DECLARE) {
				if (!FunctionBuilderVariable(tokenizer, builder, node, true)) return false;
			}

			else if (!FunctionBuilderRecurse(tokenizer, node->firstChild, builder, true)) return false;
			FunctionBuilderAddLineNumber(builder, node);
			uint8_t b = builder->isListAssignment ? T_EQUALS_LIST : builder->isDotAssignment ? T_EQUALS_DOT : T_EQUALS;
			FunctionBuilderAppend(builder, &b, sizeof(b));
			if (!builder->isListAssignment) FunctionBuilderAppend(builder, &builder->scopeIndex, sizeof(builder->scopeIndex));
			b = T_PERSIST;
			if (builder->isPersistentVariable) FunctionBuilderAppend(builder, &b, sizeof(b));
		}

		return true;
	} else if (node->type == T_CALL) {
		Node *argument = node->firstChild->sibling->firstChild;
		Node *arguments[FUNCTION_MAX_ARGUMENTS];
		size_t argumentCount = 0;

		while (argument) {
			arguments[argumentCount++] = argument;
			argument = argument->sibling;
		}

		for (uintptr_t i = 0; i < argumentCount; i++) {
			if (!FunctionBuilderRecurse(tokenizer, arguments[argumentCount - i - 1], builder, false)) {
				return false;
			}
		}

		if (!FunctionBuilderRecurse(tokenizer, node->firstChild, builder, false)) return false;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		return true;
	} else if (node->type == T_WHILE) {
		int32_t start = builder->dataBytes;
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild, builder, false)) return false;
		FunctionBuilderAddLineNumber(builder, node);
		uint8_t b = T_IF;
		FunctionBuilderAppend(builder, &b, sizeof(b));
		uintptr_t writeOffset = builder->dataBytes;
		uint32_t zero = 0;
		FunctionBuilderAppend(builder, &zero, sizeof(zero));
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild->sibling, builder, false)) return false;
		b = T_BRANCH;
		FunctionBuilderAppend(builder, &b, sizeof(b));
		int32_t delta = start - builder->dataBytes;
		FunctionBuilderAppend(builder, &delta, sizeof(delta));
		delta = builder->dataBytes - writeOffset;
		MemoryCopy(builder->data + writeOffset, &delta, sizeof(delta));
		return true;
	} else if (node->type == T_FOR) {
		Node *declare = node->firstChild;
		Node *condition = node->firstChild->sibling;
		Node *increment = node->firstChild->sibling->sibling;
		Node *body = node->firstChild->sibling->sibling->sibling;

		if (declare->type != T_DECLARE && declare->type != T_EQUALS) {
			PrintError2(tokenizer, node, "The first section of a for statement must be a variable declaration or an assignment.\n");
			return false;
		}

		if (!FunctionBuilderRecurse(tokenizer, declare, builder, false)) return false;
		int32_t start = builder->dataBytes;
		if (!FunctionBuilderRecurse(tokenizer, condition, builder, false)) return false;
		FunctionBuilderAddLineNumber(builder, node);
		uint8_t b = T_IF;
		FunctionBuilderAppend(builder, &b, sizeof(b));
		uintptr_t writeOffset = builder->dataBytes;
		uint32_t zero = 0;
		FunctionBuilderAppend(builder, &zero, sizeof(zero));
		if (!FunctionBuilderRecurse(tokenizer, body, builder, false)) return false;
		if (!FunctionBuilderRecurse(tokenizer, increment, builder, false)) return false;

		if (increment->expressionType && increment->expressionType->type != T_VOID) {
			if (increment->type == T_CALL) {
				uint8_t b = T_POP;
				FunctionBuilderAppend(builder, &b, sizeof(b));
			} else {
				PrintError2(tokenizer, increment, "The result of the expression is unused.\n");
				return false;
			}
		}

		b = T_BRANCH;
		FunctionBuilderAppend(builder, &b, sizeof(b));
		int32_t delta = start - builder->dataBytes;
		FunctionBuilderAppend(builder, &delta, sizeof(delta));
		delta = builder->dataBytes - writeOffset;
		MemoryCopy(builder->data + writeOffset, &delta, sizeof(delta));
		return true;
	} else if (node->type == T_IF) {
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild, builder, false)) return false;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		uintptr_t writeOffset = builder->dataBytes, writeOffsetElse = 0;
		uint32_t zero = 0;
		FunctionBuilderAppend(builder, &zero, sizeof(zero));
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild->sibling, builder, false)) return false;

		if (node->firstChild->sibling->sibling) {
			uint8_t b = T_BRANCH;
			FunctionBuilderAppend(builder, &b, sizeof(b));
			writeOffsetElse = builder->dataBytes;
			FunctionBuilderAppend(builder, &zero, sizeof(zero));
		}

		int32_t delta = builder->dataBytes - writeOffset;
		MemoryCopy(builder->data + writeOffset, &delta, sizeof(delta));

		if (node->firstChild->sibling->sibling) {
			if (!FunctionBuilderRecurse(tokenizer, node->firstChild->sibling->sibling, builder, false)) return false;
			delta = builder->dataBytes - writeOffsetElse;
			MemoryCopy(builder->data + writeOffsetElse, &delta, sizeof(delta));
		}

		return true;
	} else if (node->type == T_LOGICAL_OR || node->type == T_LOGICAL_AND) {
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild, builder, false)) return false;
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		uintptr_t writeOffset = builder->dataBytes;
		uint32_t zero = 0;
		FunctionBuilderAppend(builder, &zero, sizeof(zero));
		if (!FunctionBuilderRecurse(tokenizer, node->firstChild->sibling, builder, false)) return false;
		int32_t delta = builder->dataBytes - writeOffset;
		MemoryCopy(builder->data + writeOffset, &delta, sizeof(delta));
		return true;
	} else if (node->type == T_NEW) {
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		int16_t fieldCount = 0;

		if (node->firstChild->type == T_LIST) {
			fieldCount = ASTIsManagedType(node->firstChild->firstChild) ? -2 : -1;
		} else {
			Node *child = node->firstChild->resolveAs->firstChild;

			while (child) { 
				if (fieldCount == 1000) {
					PrintError2(tokenizer, child, "The struct exceeds the maximum number of fields (1000).\n");
					return false;
				}

				fieldCount++; 
				child = child->sibling; 
			}
		}

		FunctionBuilderAppend(builder, &fieldCount, sizeof(fieldCount));
		return true;
	} else if (node->type == T_COLON) {
		FunctionBuilderRecurse(tokenizer, node->firstChild, builder, false);

		Node *argument = node->firstChild->sibling->firstChild;

		while (argument) {
			FunctionBuilderRecurse(tokenizer, argument, builder, false);
			argument = argument->sibling;
		}

		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->operationType, sizeof(node->operationType));
		return true;
	}

	Node *child = node->firstChild;

	while (child) {
		if (!FunctionBuilderRecurse(tokenizer, child, builder, false)) {
			return false;
		}

		if (node->type == T_BLOCK && child->expressionType && child->expressionType->type != T_VOID) {
			if (child->type == T_CALL) {
				uint8_t b = T_POP;
				FunctionBuilderAppend(builder, &b, sizeof(b));
			} else if (child->type == T_DECLARE || child->type == T_EQUALS) {
			} else {
				PrintError2(tokenizer, child, "The result of the expression is unused.\n");
				return false;
			}
		}

		child = child->sibling;
	}

	if (node->type == T_FUNCBODY || node->type == T_BLOCK) {
		uint8_t b = T_EXIT_SCOPE;
		uint16_t entryCount = node->scope->variableEntryCount;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &b, sizeof(b));
		FunctionBuilderAppend(builder, &entryCount, sizeof(entryCount));
		b = T_END_FUNCTION;
		if (node->type == T_FUNCBODY) FunctionBuilderAppend(builder, &b, sizeof(b));
	} else if (node->type == T_RETURN) {
		uint8_t b = T_END_FUNCTION;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &b, sizeof(b));
	} else if (node->type == T_ASSERT || node->type == T_NULL || node->type == T_LOGICAL_NOT) {
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
	} else if (node->type == T_ADD || node->type == T_MINUS || node->type == T_ASTERISK || node->type == T_SLASH) {
		uint8_t b = node->expressionType->type == T_FLOAT ? node->type - T_ADD + T_FLOAT_ADD 
			: node->expressionType->type == T_STR ? T_CONCAT : node->type;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &b, sizeof(b));
	} else if (node->type == T_STR_INTERPOLATE) {
		uint8_t b = node->firstChild->sibling->expressionType->type == T_STR ? T_INTERPOLATE_STR
			: node->firstChild->sibling->expressionType->type == T_FLOAT ? T_INTERPOLATE_FLOAT
			: node->firstChild->sibling->expressionType->type == T_INT ? T_INTERPOLATE_INT
			: node->firstChild->sibling->expressionType->type == T_BOOL ? T_INTERPOLATE_BOOL : T_ERROR;
		Assert(b != T_ERROR);
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &b, sizeof(b));
	} else if (node->type == T_LESS_THAN || node->type == T_GREATER_THAN || node->type == T_LT_OR_EQUAL || node->type == T_GT_OR_EQUAL
			|| node->type == T_DOUBLE_EQUALS || node->type == T_NOT_EQUALS) {
		uint8_t b = node->firstChild->expressionType->type == T_STR ? node->type - T_DOUBLE_EQUALS + T_STR_DOUBLE_EQUALS 
			: node->firstChild->expressionType->type == T_FLOAT ? node->type - T_GREATER_THAN + T_FLOAT_GREATER_THAN : node->type;
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &b, sizeof(b));
	} else if (node->type == T_VARIABLE) {
		if (!FunctionBuilderVariable(tokenizer, builder, node, forAssignment)) {
			return false;
		}
	} else if (node->type == T_INDEX) {
		if (forAssignment) {
			if (node->firstChild->expressionType->type == T_STR) {
				PrintError2(tokenizer, node->firstChild, "Strings cannot be modified.\n");
				return false;
			} else {
				builder->isListAssignment = true;
				builder->isDotAssignment = false;
			}
		} else {
			uint8_t b = node->firstChild->expressionType->type == T_STR ? T_INDEX : T_INDEX_LIST;
			FunctionBuilderAddLineNumber(builder, node);
			FunctionBuilderAppend(builder, &b, sizeof(b));
		}
	} else if (node->type == T_DOT) {
		bool isStruct = node->firstChild->expressionType->resolveAs && node->firstChild->expressionType->resolveAs->type == T_STRUCT;

		if (isStruct) {
			Node *field = node->firstChild->expressionType->resolveAs->firstChild;
			int16_t fieldIndex = 0;

			while (field) {
				if (field->token.textBytes == node->token.textBytes && 
						0 == MemoryCompare(field->token.text, node->token.text, node->token.textBytes)) {
					break;
				}

				field = field->sibling;
				fieldIndex++;
			}

			if (ASTIsManagedType(field->firstChild)) {
				fieldIndex = -1 - fieldIndex;
			}

			if (forAssignment) {
				builder->scopeIndex = fieldIndex;
				builder->isDotAssignment = true;
				builder->isListAssignment = false;
			} else {
				FunctionBuilderAddLineNumber(builder, node);
				FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
				FunctionBuilderAppend(builder, &fieldIndex, sizeof(fieldIndex));
			}
		} else {
			if (forAssignment) {
				PrintError2(tokenizer, node, "You cannot directly modify a variable from an imported module.\n");
				return false;
			} else {
				Node *importStatement = node->firstChild->expressionType->parent;
				Assert(importStatement->type == T_IMPORT);
				uint32_t index = ScopeLookupIndex(node, importStatement->importData->rootNode->scope, false, false);
				index += importStatement->importData->globalVariableOffset;
				FunctionBuilderAddLineNumber(builder, node);
				uint8_t b = T_POP;
				FunctionBuilderAppend(builder, &b, sizeof(b));
				b = T_VARIABLE;
				FunctionBuilderAppend(builder, &b, sizeof(b));
				FunctionBuilderAppend(builder, &index, sizeof(index));
			}
		}
	} else if (node->type == T_NUMERIC_LITERAL) {
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		Value v;

		// TODO Overflow checking.

		if (node->expressionType == &globalExpressionTypeInt) {
			v.i = 0;

			for (uintptr_t i = 0; i < node->token.textBytes; i++) {
				v.i *= 10;
				v.i += node->token.text[i] - '0';
			}
		} else if (node->expressionType == &globalExpressionTypeFloat) {
			bool dot = false;
			v.f = 0;
			double m = 0.1;

			for (uintptr_t i = 0; i < node->token.textBytes; i++) {
				if (node->token.text[i] == '.') {
					dot = true;
				} else if (dot) {
					v.f += (node->token.text[i] - '0') * m;
					m /= 10;
				} else {
					v.f *= 10;
					v.f += node->token.text[i] - '0';
				}
			}
		}

		FunctionBuilderAppend(builder, &v, sizeof(v));
	} else if (node->type == T_STRING_LITERAL) {
		FunctionBuilderAddLineNumber(builder, node);
		FunctionBuilderAppend(builder, &node->type, sizeof(node->type));
		uint32_t textBytes = node->token.textBytes;
		FunctionBuilderAppend(builder, &textBytes, sizeof(textBytes));
		FunctionBuilderAppend(builder, node->token.text, textBytes);
	} else if (node->type == T_TRUE || node->type == T_FALSE) {
		FunctionBuilderAddLineNumber(builder, node);
		uint8_t b = T_NUMERIC_LITERAL;
		FunctionBuilderAppend(builder, &b, sizeof(b));
		Value v;
		v.i = node->type == T_TRUE ? 1 : 0;
		FunctionBuilderAppend(builder, &v, sizeof(v));
	} else {
		PrintDebug("FunctionBuilderRecurse %d\n", node->type);
		Assert(false);
	}

	return true;
}

bool ASTGenerate(Tokenizer *tokenizer, Node *root, ExecutionContext *context) {
	Node *child = root->firstChild;

	context->functionData->globalVariableOffset = context->variableCount;
	context->variableCount += root->scope->variableEntryCount;
	context->variablesAllocated += root->scope->variableEntryCount;
	context->variables = AllocateResize(context->variables, sizeof(Value) * context->variablesAllocated);
	context->variableIsManaged = AllocateResize(context->variableIsManaged, sizeof(Value) * context->variablesAllocated);

	for (uintptr_t i = 0; i < root->scope->variableEntryCount; i++) {
		context->variables[context->functionData->globalVariableOffset + i].i = 0;
		context->variableIsManaged[context->functionData->globalVariableOffset + i] = false;
	}

	uint8_t zero = 0; // Make sure no function can start at 0.
	FunctionBuilderAppend(context->functionData, &zero, sizeof(zero));

	while (child) {
		if (child->type == T_FUNCTION) {
			if (child->isExternalCall) {
				context->variables[context->functionData->globalVariableOffset + ScopeLookupIndex(child, root->scope, false, false)].i = context->functionData->dataBytes;
				uint8_t b = T_EXTCALL;

				uint16_t index = 0xFFFF;
				
				for (uintptr_t i = 0; i < sizeof(externalFunctions) / sizeof(externalFunctions[0]); i++) {
					bool match = true;

					for (uintptr_t j = 0; j <= child->token.textBytes; j++) {
						if (externalFunctions[i].cName[j] != (j == child->token.textBytes ? 0 : child->token.text[j])) {
							match = false;
							break;
						}
					}

					if (match) {
						index = i;
						break;
					}
				}

				if (index == 0xFFFF) {
					PrintError2(tokenizer, child, "No such external function '%.*s'.\n", child->token.textBytes, child->token.text);
					return false;
				}

				FunctionBuilderAppend(context->functionData, &b, sizeof(b));
				FunctionBuilderAppend(context->functionData, &index, sizeof(index));
			} else {
				context->variables[context->functionData->globalVariableOffset + ScopeLookupIndex(child, root->scope, false, false)].i = context->functionData->dataBytes;
				if (!FunctionBuilderRecurse(tokenizer, child->firstChild->sibling, context->functionData, false)) return false;
			}
		} else if (child->type == T_DECLARE) {
			if (child->isPersistentVariable && context->mainModule != tokenizer->module) {
				PrintError2(tokenizer, child, "Persistent variables are not allowed in imported modules.\n");
				return false;
			}

			context->variables[context->functionData->globalVariableOffset + ScopeLookupIndex(child, root->scope, false, false)].i = 0;
			context->variableIsManaged[context->functionData->globalVariableOffset + ScopeLookupIndex(child, root->scope, false, false)] = ASTIsManagedType(child->expressionType);
		}

		child = child->sibling;
	}

	return true;
}

// --------------------------------- Main script execution.

void HeapGarbageCollectMark(ExecutionContext *context, uintptr_t index) {
	Assert(index < context->heapEntriesAllocated);
	if (context->heap[index].gcMark) return;
	context->heap[index].gcMark = true;

	if (context->heap[index].type == T_EOF || context->heap[index].type == T_STR) {
		// Nothing else to mark.
	} else if (context->heap[index].type == T_STRUCT) {
		for (uintptr_t i = 0; i < context->heap[index].fieldCount; i++) {
			if (((uint8_t *) context->heap[index].fields)[-1 - i]) {
				HeapGarbageCollectMark(context, context->heap[index].fields[i].i);
			}
		}
	} else if (context->heap[index].type == T_LIST) {
		if (context->heap[index].listValuesAreManaged) {
			for (uintptr_t i = 0; i < context->heap[index].length; i++) {
				HeapGarbageCollectMark(context, context->heap[index].list[i].i);
			}
		}
	} else {
		Assert(false);
	}
}

void HeapFreeEntry(ExecutionContext *context, uintptr_t i) {
	if (context->heap[i].type == T_STR) {
		AllocateResize(context->heap[i].text, 0);
	} else if (context->heap[i].type == T_STRUCT) {
		AllocateResize((uint8_t *) context->heap[i].fields - context->heap[i].fieldCount, 0);
	} else if (context->heap[i].type == T_LIST) {
		AllocateResize(context->heap[i].list, 0);
	} else {
		Assert(false);
	}

	context->heap[i].type = T_ERROR;
}

uintptr_t HeapAllocate(ExecutionContext *context) {
	if (!context->heapFirstUnusedEntry) {
		// All heapEntriesAllocated entries are in use.

		for (uintptr_t i = 0; i < context->heapEntriesAllocated; i++) {
			context->heap[i].gcMark = false;
		}

		for (uintptr_t i = 0; i < context->variableCount; i++) {
			if (context->variableIsManaged[i]) {
				HeapGarbageCollectMark(context, context->variables[i].i);
			}
		}
		
		for (uintptr_t i = 0; i < context->stackPointer; i++) {
			if (context->stackIsManaged[i]) {
				HeapGarbageCollectMark(context, context->stack[i].i);
			}
		}

		uintptr_t *link = &context->heapFirstUnusedEntry;
		uintptr_t reclaimed = 0;

		for (uintptr_t i = 1; i < context->heapEntriesAllocated; i++) {
			if (!context->heap[i].gcMark) {
				HeapFreeEntry(context, i);
				*link = i;
				link = &context->heap[i].nextUnusedEntry;
				reclaimed++;
			}
		}

		if (reclaimed <= context->heapEntriesAllocated / 5) {
			// PrintDebug("\033[0;32mFreed only %d/%d entries. Doubling heap size...\033[0m\n", reclaimed, context->heapEntriesAllocated);

			intptr_t linkIndex = link == &context->heapFirstUnusedEntry ? -1 
				: ((intptr_t) link - (intptr_t) context->heap) / (intptr_t) sizeof(HeapEntry);
			uintptr_t oldSize = context->heapEntriesAllocated;
			context->heapEntriesAllocated *= 2;
			context->heap = (HeapEntry *) AllocateResize(context->heap, context->heapEntriesAllocated * sizeof(HeapEntry));
			link = linkIndex == -1 ? &context->heapFirstUnusedEntry : &context->heap[linkIndex].nextUnusedEntry;

			for (uintptr_t i = oldSize; i < context->heapEntriesAllocated; i++) {
				context->heap[i].type = T_ERROR;
				*link = i;
				link = &context->heap[i].nextUnusedEntry;
			}
		} else {
			// PrintDebug("\033[0;32mFreed %d/%d entries.\033[0m\n", reclaimed, context->heapEntriesAllocated);
		}

		*link = 0;
	}

	uintptr_t index = context->heapFirstUnusedEntry;
	Assert(index);
	context->heapFirstUnusedEntry = context->heap[index].nextUnusedEntry;
	return index;
}

void ScriptPrintNode(Node *node, int indent) {
	for (int i = 0; i < indent; i++) {
		PrintDebug("\t");
	}

	PrintDebug("%d l%d '%.*s'\n", node->type, node->token.line, node->token.textBytes, node->token.text);

	Node *child = node->firstChild;

	while (child) {
		ScriptPrintNode(child, indent + 1);
		child = child->sibling;
	}
}

int ScriptExecuteFunction(uintptr_t instructionPointer, ExecutionContext *context) {
	// TODO Things to verify if loading untrusted scripts -- is this a feature we will need?
	// 	Checking we don't go off the end of the function body.
	// 	Checking that this is actually a valid function body pointer.
	// 	Checking various integer overflows.

	uintptr_t variableBase = context->variableCount - 1;
	uint8_t *functionData = context->functionData->data;

	while (true) {
		uint8_t command = functionData[instructionPointer++];

		if (command == T_BLOCK || command == T_FUNCBODY) {
			uint16_t newVariableCount = functionData[instructionPointer + 0] + (functionData[instructionPointer + 1] << 8); 
			instructionPointer += 2;

			if (context->variableCount + newVariableCount > context->variablesAllocated) {
				// TODO Handling memory errors here.
				context->variablesAllocated = context->variableCount + newVariableCount;
				context->variables = AllocateResize(context->variables, context->variablesAllocated * sizeof(Value)); 
				context->variableIsManaged = AllocateResize(context->variableIsManaged, context->variablesAllocated * sizeof(bool)); 
			}

			MemoryCopy(context->variableIsManaged + context->variableCount, functionData + instructionPointer, newVariableCount);
			instructionPointer += newVariableCount;

			for (uintptr_t i = context->variableCount; i < context->variableCount + newVariableCount; i++) {
				if (command == T_FUNCBODY) {
					if (context->stackPointer < 1) return -1;
					context->variables[i] = context->stack[--context->stackPointer];
				} else {
					Value zero = { 0 };
					context->variables[i] = zero;
				}
			}

			context->variableCount += newVariableCount;
		} else if (command == T_EXIT_SCOPE) {
			uint16_t count = functionData[instructionPointer + 0] + (functionData[instructionPointer + 1] << 8); 
			instructionPointer += 2;
			if (context->variableCount < count) return -1;
			context->variableCount -= count;
		} else if (command == T_NUMERIC_LITERAL) {
			if (context->stackPointer == context->stackEntriesAllocated) {
				PrintError4(context, instructionPointer - 1, "Stack overflow.\n");
				return 0;
			}

			context->stackIsManaged[context->stackPointer] = false;
			MemoryCopy(&context->stack[context->stackPointer++], &functionData[instructionPointer], sizeof(Value));
			instructionPointer += sizeof(Value);
		} else if (command == T_NULL) {
			if (context->stackPointer == context->stackEntriesAllocated) {
				PrintError4(context, instructionPointer - 1, "Stack overflow.\n");
				return 0;
			}

			context->stackIsManaged[context->stackPointer] = true;
			context->stack[context->stackPointer++].i = 0;
		} else if (command == T_STRING_LITERAL) {
			if (context->stackPointer == context->stackEntriesAllocated) {
				PrintError4(context, instructionPointer - 1, "Stack overflow.\n");
				return 0;
			}

			uint32_t textBytes;
			MemoryCopy(&textBytes, &functionData[instructionPointer], sizeof(textBytes));
			instructionPointer += sizeof(textBytes);

			// TODO Handle memory allocation failures here.
			uintptr_t index = HeapAllocate(context);
			context->heap[index].type = T_STR;
			context->heap[index].text = (char *) AllocateResize(NULL, textBytes);
			context->heap[index].bytes = textBytes;
			MemoryCopy(context->heap[index].text, &functionData[instructionPointer], textBytes);
			instructionPointer += textBytes;

			Value v;
			v.i = index;
			context->stackIsManaged[context->stackPointer] = true;
			context->stack[context->stackPointer++] = v;
		} else if (command == T_CONCAT) {
			if (context->stackPointer < 2) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index1 = context->stack[context->stackPointer - 2].i;
			if (context->heapEntriesAllocated <= index1) return -1;
			HeapEntry *entry1 = &context->heap[index1];
			if (entry1->type != T_EOF && entry1->type != T_STR) return -1;
			const char *text1 = entry1->type == T_STR ? entry1->text : "";
			size_t bytes1 = entry1->type == T_STR ? entry1->bytes : 0;

			uint64_t index2 = context->stack[context->stackPointer - 1].i;
			if (context->heapEntriesAllocated <= index2) return -1;
			HeapEntry *entry2 = &context->heap[index2];
			if (entry2->type != T_EOF && entry2->type != T_STR) return -1;
			const char *text2 = entry2->type == T_STR ? entry2->text : "";
			size_t bytes2 = entry2->type == T_STR ? entry2->bytes : 0;

			// TODO Handle memory allocation failures here.
			uintptr_t index = HeapAllocate(context);
			context->heap[index].type = T_STR;
			context->heap[index].bytes = bytes1 + bytes2;
			context->heap[index].text = (char *) AllocateResize(NULL, context->heap[index].bytes);
			if (bytes1) MemoryCopy(context->heap[index].text + 0,      text1, bytes1);
			if (bytes2) MemoryCopy(context->heap[index].text + bytes1, text2, bytes2);
			context->stack[context->stackPointer - 2].i = index;

			context->stackPointer--;
		} else if (command == T_INTERPOLATE_STR || command == T_INTERPOLATE_BOOL 
				|| command == T_INTERPOLATE_INT || command == T_INTERPOLATE_FLOAT) {
			if (context->stackPointer < 3) return -1;
			if (!context->stackIsManaged[context->stackPointer - 3]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index1 = context->stack[context->stackPointer - 3].i;
			if (context->heapEntriesAllocated <= index1) return -1;
			HeapEntry *entry1 = &context->heap[index1];
			if (entry1->type != T_EOF && entry1->type != T_STR) return -1;
			const char *text1 = entry1->type == T_STR ? entry1->text : "";
			size_t bytes1 = entry1->type == T_STR ? entry1->bytes : 0;

			const char *text2 = "";
			size_t bytes2 = 0;
			char temp[30];

			if (command == T_INTERPOLATE_STR) {
				if (!context->stackIsManaged[context->stackPointer - 2]) return -1;
				uint64_t index2 = context->stack[context->stackPointer - 2].i;
				if (context->heapEntriesAllocated <= index2) return -1;
				HeapEntry *entry2 = &context->heap[index2];
				if (entry2->type != T_EOF && entry2->type != T_STR) return -1;
				text2 = entry2->type == T_STR ? entry2->text : "";
				bytes2 = entry2->type == T_STR ? entry2->bytes : 0;
			} else if (command == T_INTERPOLATE_BOOL) {
				text2 = context->stack[context->stackPointer - 2].i ? "true" : "false";
				bytes2 = context->stack[context->stackPointer - 2].i ? 4 : 5;
			} else if (command == T_INTERPOLATE_INT) {
				text2 = temp;
				bytes2 = PrintIntegerToBuffer(temp, sizeof(temp), context->stack[context->stackPointer - 2].i);
			} else if (command == T_INTERPOLATE_FLOAT) {
				text2 = temp;
				bytes2 = PrintFloatToBuffer(temp, sizeof(temp), context->stack[context->stackPointer - 2].f);
			}

			uint64_t index3 = context->stack[context->stackPointer - 1].i;
			if (context->heapEntriesAllocated <= index3) return -1;
			HeapEntry *entry3 = &context->heap[index3];
			if (entry3->type != T_EOF && entry3->type != T_STR) return -1;
			const char *text3 = entry3->type == T_STR ? entry3->text : "";
			size_t bytes3 = entry3->type == T_STR ? entry3->bytes : 0;

			// TODO Handle memory allocation failures here.
			uintptr_t index = HeapAllocate(context);
			context->heap[index].type = T_STR;
			context->heap[index].bytes = bytes1 + bytes2 + bytes3;
			context->heap[index].text = (char *) AllocateResize(NULL, context->heap[index].bytes);
			if (bytes1) MemoryCopy(context->heap[index].text + 0,               text1, bytes1);
			if (bytes2) MemoryCopy(context->heap[index].text + bytes1,          text2, bytes2);
			if (bytes3) MemoryCopy(context->heap[index].text + bytes1 + bytes2, text3, bytes3);
			context->stack[context->stackPointer - 3].i = index;

			context->stackPointer -= 2;
		} else if (command == T_VARIABLE) {
			if (context->stackPointer == context->stackEntriesAllocated) {
				PrintDebug("Stack overflow.\n");
				return -1;
			}

			int32_t scopeIndex;
			MemoryCopy(&scopeIndex, &functionData[instructionPointer], sizeof(scopeIndex));
			if (scopeIndex < 0) scopeIndex = variableBase - scopeIndex;

			if ((uintptr_t) scopeIndex >= context->variableCount) {
				return -1;
			}

			instructionPointer += sizeof(scopeIndex);
			context->stackIsManaged[context->stackPointer] = context->variableIsManaged[scopeIndex];
			context->stack[context->stackPointer++] = context->variables[scopeIndex];
		} else if (command == T_EQUALS) {
			int32_t scopeIndex;
			MemoryCopy(&scopeIndex, &functionData[instructionPointer], sizeof(scopeIndex));
			instructionPointer += sizeof(scopeIndex);
			if (scopeIndex < 0) scopeIndex = variableBase - scopeIndex;

			if ((uintptr_t) scopeIndex >= context->variableCount || !context->stackPointer) {
				return -1;
			}

			if (context->variableIsManaged[scopeIndex] != context->stackIsManaged[context->stackPointer - 1]) {
				return -1;
			}

			context->variables[scopeIndex] = context->stack[--context->stackPointer];
		} else if (command == T_EQUALS_DOT) {
			if (context->stackPointer < 2) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index = context->stack[context->stackPointer - 1].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The struct is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_STRUCT) return -1;

			int32_t fieldIndex;
			MemoryCopy(&fieldIndex, &functionData[instructionPointer], sizeof(fieldIndex));
			instructionPointer += sizeof(fieldIndex);
			bool isManaged = fieldIndex < 0;
			if (isManaged) fieldIndex = -fieldIndex - 1;
			if (fieldIndex < 0 || fieldIndex >= entry->fieldCount) return -1;

			entry->fields[fieldIndex] = context->stack[context->stackPointer - 2];
			if (isManaged != context->stackIsManaged[context->stackPointer - 2]) return -1;
			((uint8_t *) entry->fields - 1)[-fieldIndex] = isManaged;

			context->stackPointer -= 2;
		} else if (command == T_EQUALS_LIST) {
			if (context->stackPointer < 3) return -1;
			if (context->stackIsManaged[context->stackPointer - 1]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;

			uint64_t index = context->stack[context->stackPointer - 2].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The list is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_LIST) return -1;

			index = context->stack[context->stackPointer - 1].i;

			if (index >= entry->length) {
				PrintError4(context, instructionPointer - 1, "The index %ld is not valid for the list, which has length %d.\n", index, entry->length);
				return 0;
			}

			entry->list[index] = context->stack[context->stackPointer - 3];
			if (entry->listValuesAreManaged != context->stackIsManaged[context->stackPointer - 3]) return -1;

			context->stackPointer -= 3;
		} else if (command == T_INDEX_LIST) {
			if (context->stackPointer < 2) return -1;
			if (context->stackIsManaged[context->stackPointer - 1]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;

			uint64_t index = context->stack[context->stackPointer - 2].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The list is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_LIST) return -1;

			index = context->stack[context->stackPointer - 1].i;

			if (index >= entry->length) {
				PrintError4(context, instructionPointer - 1, "The index %ld is not valid for the list, which has length %d.\n", index, entry->length);
				return 0;
			}

			context->stack[context->stackPointer - 2] = entry->list[index];
			context->stackIsManaged[context->stackPointer - 2] = entry->listValuesAreManaged;
			context->stackPointer--;
		} else if (command == T_OP_FIRST || command == T_OP_LAST) {
			if (context->stackPointer < 1) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index = context->stack[context->stackPointer - 1].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The list is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_LIST) return -1;

			if (!entry->length) {
				PrintError4(context, instructionPointer - 1, "The list is empty.\n");
				return 0;
			}

			context->stack[context->stackPointer - 1] = entry->list[command == T_OP_FIRST ? 0 : entry->length - 1];
			context->stackIsManaged[context->stackPointer - 1] = entry->listValuesAreManaged;
		} else if (command == T_DOT) {
			if (context->stackPointer < 1) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index = context->stack[context->stackPointer - 1].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The struct is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_STRUCT) return -1;

			int16_t fieldIndex;
			MemoryCopy(&fieldIndex, &functionData[instructionPointer], sizeof(fieldIndex));
			instructionPointer += sizeof(fieldIndex);
			bool isManaged = fieldIndex < 0;
			if (isManaged) fieldIndex = -fieldIndex - 1;
			if (fieldIndex < 0 || fieldIndex >= entry->fieldCount) return -1;

			// Only allow the isManaged bool to be incorrect if it's a null managed variable.
			if (isManaged != ((uint8_t *) entry->fields - 1)[-fieldIndex] && (entry->fields[fieldIndex].i || !isManaged)) return -1;

			context->stack[context->stackPointer - 1] = entry->fields[fieldIndex];
			context->stackIsManaged[context->stackPointer - 1] = isManaged;
		} else if (command == T_ADD) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i + context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_MINUS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i - context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_ASTERISK) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i * context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_SLASH) {
			if (context->stackPointer < 2) return -1;

			if (0 == context->stack[context->stackPointer - 1].i) {
				PrintError4(context, instructionPointer - 1, "Attempted division by zero.\n");
				return 0;
			}

			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f / context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_ADD) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].f = context->stack[context->stackPointer - 2].f + context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_MINUS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].f = context->stack[context->stackPointer - 2].f - context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_ASTERISK) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].f = context->stack[context->stackPointer - 2].f * context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_SLASH) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].f = context->stack[context->stackPointer - 2].f / context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_LESS_THAN) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i < context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_GREATER_THAN) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i > context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_LT_OR_EQUAL) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i <= context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_GT_OR_EQUAL) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i >= context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_DOUBLE_EQUALS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i == context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_NOT_EQUALS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].i != context->stack[context->stackPointer - 1].i;
			context->stackPointer--;
		} else if (command == T_LOGICAL_NOT) {
			if (context->stackPointer < 1) return -1;
			context->stack[context->stackPointer - 1].i = !context->stack[context->stackPointer - 1].i;
		} else if (command == T_FLOAT_LESS_THAN) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f < context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_GREATER_THAN) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f > context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_LT_OR_EQUAL) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f <= context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_GT_OR_EQUAL) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f >= context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_DOUBLE_EQUALS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f == context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_FLOAT_NOT_EQUALS) {
			if (context->stackPointer < 2) return -1;
			context->stack[context->stackPointer - 2].i = context->stack[context->stackPointer - 2].f != context->stack[context->stackPointer - 1].f;
			context->stackPointer--;
		} else if (command == T_STR_DOUBLE_EQUALS || command == T_STR_NOT_EQUALS) {
			if (context->stackPointer < 2) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;

			uint64_t index1 = context->stack[context->stackPointer - 2].i;
			if (context->heapEntriesAllocated <= index1) return -1;
			HeapEntry *entry1 = &context->heap[index1];
			if (entry1->type != T_EOF && entry1->type != T_STR) return -1;
			const char *text1 = entry1->type == T_STR ? entry1->text : 0;
			size_t bytes1 = entry1->type == T_STR ? entry1->bytes : 0;

			uint64_t index2 = context->stack[context->stackPointer - 1].i;
			if (context->heapEntriesAllocated <= index2) return -1;
			HeapEntry *entry2 = &context->heap[index2];
			if (entry2->type != T_EOF && entry2->type != T_STR) return -1;
			const char *text2 = entry2->type == T_STR ? entry2->text : 0;
			size_t bytes2 = entry2->type == T_STR ? entry2->bytes : 0;

			bool equal = bytes1 == bytes2 && 0 == MemoryCompare(text1, text2, bytes1);

			context->stack[context->stackPointer - 2].i = command == T_STR_NOT_EQUALS ? !equal : equal;
			context->stackIsManaged[context->stackPointer - 2] = false;

			context->stackPointer--;
		} else if (command == T_OP_LEN) {
			if (context->stackPointer < 1) return -1;
			if (!context->stackIsManaged[context->stackPointer - 1]) return -1;
			uint64_t index = context->stack[context->stackPointer - 1].i;
			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			int64_t length;
			if (entry->type == T_EOF) length = 0;
			else if (entry->type == T_STR) length = entry->bytes;
			else if (entry->type == T_LIST) length = entry->length;
			else return -1;
			context->stack[context->stackPointer - 1].i = length;
			context->stackIsManaged[context->stackPointer - 1] = false;
		} else if (command == T_INDEX) {
			if (context->stackPointer < 1) return -1;
			if (context->stackIsManaged[context->stackPointer - 1]) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;
			uint64_t index = context->stack[context->stackPointer - 2].i;
			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_EOF && entry->type != T_STR) return -1;
			index = context->stack[context->stackPointer - 1].i;
			size_t bytes = entry->type == T_STR ? entry->bytes : 0;

			if (index >= bytes) {
				PrintError4(context, instructionPointer - 1, "Index %ld out of bounds in string '%.*s' of length %ld.\n", 
						index, bytes, entry->type == T_STR ? entry->text : "", bytes);
				return 0;
			}

			char c = entry->text[index];
			index = HeapAllocate(context);
			context->heap[index].type = T_STR;
			context->heap[index].bytes = 1;
			context->heap[index].text = (char *) AllocateResize(NULL, 1); // TODO Handling allocation failure.
			context->heap[index].text[0] = c;
			context->stack[context->stackPointer - 2].i = index;
			context->stackIsManaged[context->stackPointer - 2] = true;
			context->stackPointer--;
		} else if (command == T_CALL) {
			if (context->stackPointer < 1) return -1;
			BackTraceLink link;
			link.previous = context->backTrace;
			link.instructionPointer = instructionPointer;
			Value newBody = context->stack[--context->stackPointer];

			if (newBody.i == 0) {
				PrintError4(context, instructionPointer - 1, "Function pointer was null.\n");
				return 0;
			}

			context->backTrace = &link;
			int value = ScriptExecuteFunction(newBody.i, context);
			context->backTrace = link.previous;
			if (value <= 0) return value;
		} else if (command == T_EXTCALL) {
			uint16_t index = functionData[instructionPointer + 0] + (functionData[instructionPointer + 1] << 8); 
			instructionPointer += 2;

			if (index < sizeof(externalFunctions) / sizeof(externalFunctions[0])) {
				Value returnValue;
				int result = externalFunctions[index].callback(context, &returnValue);
				if (result <= 0) return result;

				if (result == 2 || result == 3) {
					if (context->stackPointer == context->stackEntriesAllocated) {
						PrintDebug("Evaluation stack overflow.\n");
						return -1;
					}

					context->stackIsManaged[context->stackPointer] = result == 3;
					context->stack[context->stackPointer++] = returnValue;
				}
			} else {
				return -1;
			}

			context->variableCount = variableBase + 1;
			break;
		} else if (command == T_IF) {
			if (context->stackPointer < 1) return -1;
			Value condition = context->stack[--context->stackPointer];
			int32_t delta;
			MemoryCopy(&delta, &functionData[instructionPointer], sizeof(delta));
			instructionPointer += condition.i ? (int32_t) sizeof(delta) : delta; 
		} else if (command == T_LOGICAL_OR) {
			if (context->stackPointer < 1) return -1;
			Value condition = context->stack[context->stackPointer - 1];
			int32_t delta;
			MemoryCopy(&delta, &functionData[instructionPointer], sizeof(delta));
			instructionPointer += condition.i ? delta : (int32_t) sizeof(delta); 
			if (!condition.i) context->stackPointer--;
		} else if (command == T_LOGICAL_AND) {
			if (context->stackPointer < 1) return -1;
			Value condition = context->stack[context->stackPointer - 1];
			int32_t delta;
			MemoryCopy(&delta, &functionData[instructionPointer], sizeof(delta));
			instructionPointer += condition.i ? (int32_t) sizeof(delta) : delta; 
			if (condition.i) context->stackPointer--;
		} else if (command == T_BRANCH) {
			int32_t delta;
			MemoryCopy(&delta, &functionData[instructionPointer], sizeof(delta));
			instructionPointer += delta; 
		} else if (command == T_POP) {
			if (context->stackPointer < 1) return -1;
			context->stackPointer--;
		} else if (command == T_ASSERT) {
			if (context->stackPointer < 1) return -1;
			Value condition = context->stack[--context->stackPointer];

			if (condition.i == 0) {
				PrintError4(context, instructionPointer - 1, "Assertion failed.\n");
				return 0;
			}
		} else if (command == T_PERSIST) {
			if (!ExternalPersistWrite(context, NULL)) {
				return 0;
			}
		} else if (command == T_NEW) {
			if (context->stackPointer == context->stackEntriesAllocated) {
				PrintError4(context, instructionPointer - 1, "Stack overflow.\n");
				return 0;
			}

			int16_t fieldCount = functionData[instructionPointer + 0] + (functionData[instructionPointer + 1] << 8); 
			instructionPointer += 2;
			uintptr_t index = HeapAllocate(context);
			context->heap[index].type = fieldCount < 0 ? T_LIST : T_STRUCT;

			if (fieldCount >= 0) {
				context->heap[index].fields = (Value *) ((uint8_t *) AllocateResize(NULL, fieldCount * (1 + sizeof(Value))) + fieldCount);
				context->heap[index].fieldCount = fieldCount;

				for (intptr_t i = 0; i < fieldCount; i++) {
					context->heap[index].fields[i].i = 0;

					// Default all fields to being unmanaged.
					// The first type they are set this will be updated.
					((uint8_t *) context->heap[index].fields)[-1 - i] = false;
				}
			} else {
				context->heap[index].listValuesAreManaged = fieldCount == -2;
				context->heap[index].length = context->heap[index].allocated = 0;
				context->heap[index].list = NULL;
			}

			Value v;
			v.i = index;
			context->stackIsManaged[context->stackPointer] = true;
			context->stack[context->stackPointer++] = v;
		} else if (command == T_OP_RESIZE) {
			if (context->stackPointer < 1) return -1;
			if (!context->stackIsManaged[context->stackPointer - 2]) return -1;

			uint64_t index = context->stack[context->stackPointer - 2].i;

			if (!index) {
				PrintError4(context, instructionPointer - 1, "The list is null.\n");
				return 0;
			}

			if (context->heapEntriesAllocated <= index) return -1;
			HeapEntry *entry = &context->heap[index];
			if (entry->type != T_LIST) return -1;

			int64_t newLength = context->stack[context->stackPointer - 1].i;

			if (newLength < 0 || newLength >= 1000000000) {
				PrintError4(context, instructionPointer - 1, "The new length of the list is out of the supported range (0..1000000000).\n");
				return 0;
			}

			uint32_t oldLength = context->heap[index].length;
			context->heap[index].length = newLength;
			context->heap[index].allocated = newLength;

			// TODO Handling out of memory errors.
			context->heap[index].list = AllocateResize(context->heap[index].list, newLength * sizeof(Value));

			for (uintptr_t i = oldLength; i < (size_t) newLength; i++) {
				context->heap[index].list[i].i = 0;
			}

			context->stackPointer -= 2;
		} else if (command == T_END_FUNCTION) {
			context->variableCount = variableBase + 1;
			break;
		} else {
			PrintDebug("Unknown command %d.\n", command);
			return -1;
		}
	}

	return true;
}

bool ScriptParseOptions(ExecutionContext *context) {
	for (uintptr_t i = 0; i < optionCount; i++) {
		uintptr_t equalsPosition = 0;
		uintptr_t optionLength = 0;

		for (uintptr_t j = 0; options[i][j]; j++) {
			if (options[i][j] == '=') {
				equalsPosition = j;
				break;
			}
		}

		for (uintptr_t j = 0; options[i][j]; j++) {
			optionLength++;
		}

		if (!equalsPosition) {
			PrintError3("Invalid script option passed on command line '%s'.\n", options[i]);
			return false;
		}

		uintptr_t index = 0;
		Node *node = NULL;

		for (uintptr_t j = 0; j < context->rootNode->scope->entryCount; j++) {
			if (context->rootNode->scope->entries[j]->token.textBytes == equalsPosition
					&& 0 == MemoryCompare(context->rootNode->scope->entries[j]->token.text, options[i], equalsPosition)
					&& context->rootNode->scope->entries[j]->type == T_DECLARE) {
				node = context->rootNode->scope->entries[j];
				break;
			}

			if (ScopeIsVariableType(context->rootNode->scope->entries[j])) {
				index++;
			}
		}

		if (!node) {
			continue;
		}

		index += context->functionData->globalVariableOffset;

		if (node->expressionType->type == T_STR) {
			uintptr_t heapIndex = HeapAllocate(context);
			context->heap[heapIndex].type = T_STR;
			context->heap[heapIndex].bytes = optionLength - equalsPosition - 1;
			context->heap[heapIndex].text = AllocateResize(NULL, context->heap[heapIndex].bytes);
			context->variables[index].i = heapIndex;
			MemoryCopy(context->heap[heapIndex].text, options[i] + equalsPosition + 1, context->heap[heapIndex].bytes);
		} else if (node->expressionType->type == T_INT) {
			// TODO Overflow checking.

			Value v;
			v.i = 0;

			for (uintptr_t j = 0; options[i][j + equalsPosition + 1]; j++) {
				char c = options[i][j + equalsPosition + 1];

				if (c >= '0' && c <= '9') {
					v.i *= 10;
					v.i += c - '0';
				} else {
					PrintError3("Option '%s' should be an integer.\n", options[i]);
					return false;
				}
			}

			context->variables[index] = v;
		} else if (node->expressionType->type == T_BOOL) {
			char c = options[i][equalsPosition + 1];
			bool truthy = c == 't' || c == 'y' || c == '1';
			bool falsey = c == 'f' || c == 'n' || c == '0';

			if (!truthy && !falsey) {
				PrintError3("#option variable '%.*s' should be a boolean value 'true' or 'false'.\n", node->token.textBytes, node->token.text);
				return false;
			}

			context->variables[index].i = truthy ? 1 : 0;
		} else {
			PrintError3("#option variable '%.*s' is not of string, boolean or integer type.\n", node->token.textBytes, node->token.text);
			return false;
		}

		if (optionsMatched[i]) {
			PrintError3("Script option passed on command line '%s' matches multiple #option variables in different modules.\n", options[i]);
			return false;
		}

		optionsMatched[i] = true;
	}

	return true;
}

bool ScriptLoad(Tokenizer tokenizer, ExecutionContext *context, ImportData *importData) {
	Node *previousRootNode = context->rootNode;
	ImportData *previousImportData = context->functionData->importData;

	context->rootNode = ParseRoot(&tokenizer); 
	context->functionData->importData = tokenizer.module;

	bool success = context->rootNode 
		&& ASTSetScopes(&tokenizer, context, context->rootNode, NULL)
		&& ASTLookupTypeIdentifiers(&tokenizer, context->rootNode)
		&& ASTSetTypes(&tokenizer, context->rootNode)
		&& ASTCheckForReturnStatements(&tokenizer, context->rootNode)
		&& ASTGenerate(&tokenizer, context->rootNode, context)
		&& ScriptParseOptions(context);

	importData->globalVariableOffset = context->functionData->globalVariableOffset;
	importData->rootNode = context->rootNode;
	*importedModulesLink = importData;
	importedModulesLink = &importData->nextImport;

	context->rootNode = previousRootNode;
	context->functionData->importData = previousImportData;

	return success;
}

int ScriptExecute(ExecutionContext *context, ImportData *mainModule) {
	bool optionMatchingError = false;

	for (uintptr_t i = 0; i < optionCount; i++) {
		if (!optionsMatched[i]) {
			PrintError3("Script option passed on command line '%s' does not match any #option variable.\n", options[i]);
			optionMatchingError = true;
		}
	}

	if (optionMatchingError) {
		return 1;
	}

	Node n;
	n.token.textBytes = 5;
	n.token.text = "Start";
	intptr_t startIndex = ScopeLookupIndex(&n, mainModule->rootNode->scope, true, false);

	if (startIndex == -1) {
		PrintError3("The script does not have a 'Start' function.\n");
		return 1;
	}

	ImportData *module = importedModules;

	while (module) {
		Node n;
		n.token.textBytes = 10;
		n.token.text = "Initialise";
		intptr_t index = ScopeLookupIndex(&n, module->rootNode->scope, true, false);

		if (index != -1) {
			int result = ScriptExecuteFunction(context->variables[index + module->globalVariableOffset].i, context);

			if (result == 0) {
				// A runtime error occurred.
				return 1;
			} else if (result == -1 || context->stackPointer != 0) {
				PrintError3("The script was malformed.\n");
				return 1;
			}
		}

		module = module->nextImport;
	}

	int result = ScriptExecuteFunction(context->variables[context->functionData->globalVariableOffset + startIndex].i, context);

	if (result == 0) {
		// A runtime error occurred.
		return 1;
	} else if (result == -1 || context->stackPointer != 0) {
		PrintError3("The script was malformed.\n");
		return 1;
	}

	return 0;
}

void ScriptFree(ExecutionContext *context) {
	ImportData *module = importedModules;

	while (module) {
		if (module->pathBytes != 15 || 0 != MemoryCompare(module->path, "__base_module__", module->pathBytes)) {
			AllocateResize(module->fileData, 0);
		}

		ASTFreeScopes(module->rootNode);
		module = module->nextImport;
	}

	for (uintptr_t i = 1; i < context->heapEntriesAllocated; i++) {
		if (context->heap[i].type != T_ERROR) {
			HeapFreeEntry(context, i);
		}
	}

	AllocateResize(context->heap, 0);
	AllocateResize(context->variables, 0);
	AllocateResize(context->variableIsManaged, 0);
	AllocateResize(context->functionData->lineNumbers, 0);
	AllocateResize(context->functionData->data, 0);
	AllocateResize(context->scriptPersistFile, 0);
}

// --------------------------------- Platform layer.

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define getcwd _getcwd
#define popen _popen
#define pclose _pclose
#define setenv(x, y, z) !SetEnvironmentVariable(x, y)
#else
#include <dirent.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void **fixedAllocationBlocks;
uint8_t *fixedAllocationCurrentBlock;
uintptr_t fixedAllocationCurrentPosition;
size_t fixedAllocationCurrentSize;

int ExternalStringTrim(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	if (entry->type == T_EOF) { returnValue->i = 0; return 3; }
	if (entry->type != T_STR) return -1;

	uintptr_t start = 0, end = entry->bytes;

	while (start != end) {
		if (entry->text[start] == ' ' || entry->text[start] == '\t' || entry->text[start] == '\r' || entry->text[start] == '\n') {
			start++;
		} else {
			break;
		}
	}

	while (start != end) {
		if (entry->text[end - 1] == ' ' || entry->text[end - 1] == '\t' || entry->text[end - 1] == '\r' || entry->text[end - 1] == '\n') {
			end--;
		} else {
			break;
		}
	}

	char *buffer = AllocateResize(NULL, end - start);
	MemoryCopy(buffer, entry->text + start, end - start);

	// TODO Handling allocation failures.
	index = HeapAllocate(context);
	context->heap[index].type = T_STR;
	context->heap[index].bytes = end - start;
	context->heap[index].text = buffer;
	returnValue->i = index;

	return 3;
}

int ExternalStringToByte(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	if (entry->type == T_EOF) { returnValue->i = -1; return 2; }
	if (entry->type != T_STR) return -1;
	returnValue->i = entry->bytes ? entry->text[0] : -1;
	return 2;
}

int ExternalSystemShellExecute(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	if (entry->type != T_STR && entry->type != T_EOF) return -1;
	const char *text = entry->type == T_STR ? entry->text : "";
	size_t bytes = entry->type == T_STR ? entry->bytes : 0;
	char *temporary = malloc(bytes + 1);

	if (temporary) {
		memcpy(temporary, text, bytes);
		temporary[bytes] = 0;
		PrintDebug("\033[0;32m%s\033[0m\n", temporary);
		returnValue->i = system(temporary) == 0;
		free(temporary);
	} else {
		fprintf(stderr, "Error in ExternalSystemShellExecute: Out of memory.\n");
		returnValue->i = 0;
	}

	return 2;
}

int ExternalSystemShellExecuteWithWorkingDirectory(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 2) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	uint64_t index2 = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	if (context->heapEntriesAllocated <= index2) return -1;
	HeapEntry *entry = &context->heap[index];
	HeapEntry *entry2 = &context->heap[index2];
	returnValue->i = 0;
	if (entry->type == T_EOF || entry2->type == T_EOF) return 2;
	if (entry2->type != T_STR) return -1;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 3;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	char *temporary2 = malloc(entry2->bytes + 1);
	memcpy(temporary2, entry2->text, entry2->bytes);
	temporary2[entry2->bytes] = 0;

	char *data = (char *) malloc(10000);

	if (!data || data != getcwd(data, 10000)) {
		PrintError4(context, 0, "Could not get the working directory.\n");
		free(data);
		return 0;
	}

	chdir(temporary);
	PrintDebug("\033[0;32m(%s) %s\033[0m\n", temporary, temporary2);
	returnValue->i = system(temporary2) == 0;
	chdir(data);

	free(temporary);
	free(temporary2);
	free(data);
	return 2;
}

int ExternalSystemShellEvaluate(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	if (entry->type != T_STR && entry->type != T_EOF) return -1;
	const char *text = entry->type == T_STR ? entry->text : "";
	size_t bytes = entry->type == T_STR ? entry->bytes : 0;
	char *temporary = malloc(bytes + 1);

	if (temporary) {
		memcpy(temporary, text, bytes);
		temporary[bytes] = 0;
		FILE *f = popen(temporary, "r");
		
		if (f) {
			char *buffer = NULL;
			size_t position = 0;
			size_t bufferAllocated = 0;

			while (true) {
				if (position == bufferAllocated) {
					bufferAllocated = bufferAllocated ? bufferAllocated * 2 : 64;
					char *reallocated = (char *) realloc(buffer, bufferAllocated);
					if (!reallocated) break;
					buffer = reallocated;
				}

				intptr_t bytesRead = fread(buffer + position, 1, bufferAllocated - position, f);

				if (bytesRead <= 0) {
					break;
				}

				position += bytesRead;
			}

			buffer = (char *) realloc(buffer, position); // Shrink to match the size exactly.
			pclose(f);

			uintptr_t index = HeapAllocate(context);
			context->heap[index].type = T_STR;
			context->heap[index].bytes = position;
			context->heap[index].text = buffer;
			returnValue->i = index;
		} else {
			returnValue->i = 0;
		}

		free(temporary);
	} else {
		fprintf(stderr, "Error in ExternalSystemShellEvaluate: Out of memory.\n");
		returnValue->i = 0;
	}

	return 3;
}

int ExternalPrintStdErr(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	if (entry->type == T_STR) fprintf(stderr, "%.*s", (int) entry->bytes, (char *) entry->text);
	else if (entry->type != T_EOF) return -1;
	return 1;
}

int ExternalPrintStdErrWarning(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	static int coloredOutput = 0;
#ifndef _WIN32
	if (!coloredOutput) coloredOutput = isatty(STDERR_FILENO) ? 2 : 1;
#endif
	if (entry->type == T_STR) fprintf(stderr, coloredOutput == 2 ? "\033[0;33m%.*s\033[0;m" : "%.*s", 
			(int) entry->bytes, (char *) entry->text);
	else if (entry->type != T_EOF) return -1;
	return 1;
}

int ExternalPrintStdErrHighlight(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	static int coloredOutput = 0;
#ifndef _WIN32
	if (!coloredOutput) coloredOutput = isatty(STDERR_FILENO) ? 2 : 1;
#endif
	if (entry->type == T_STR) fprintf(stderr, coloredOutput == 2 ? "\033[0;36m%.*s\033[0;m" : "%.*s", 
			(int) entry->bytes, (char *) entry->text);
	else if (entry->type != T_EOF) return -1;
	return 1;
}

int ExternalPathCreateDirectory(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	returnValue->i = 1;
#ifdef _WIN32
#pragma message ("ExternalPathCreateDirectory unimplemented")
	returnValue->i = 0;
#else
	if (mkdir(temporary, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) returnValue->i = errno == EEXIST;
#endif
	free(temporary);
	return 2;
}

int ExternalPathDelete(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	returnValue->i = unlink(temporary) == 0;
	free(temporary);
	return 2;
}

int ExternalPathExists(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	struct stat s = { 0 };
	returnValue->i = stat(temporary, &s) == 0;
	free(temporary);
	return 2;
}

bool PathDeleteRecursively(const char *path) {
#ifdef _WIN32
#pragma message ("PathDeleteRecursively unimplemented")
	return false;
#else
	struct stat s = {};

	if (lstat(path, &s)) {
		return true;
	}

	if (S_ISDIR(s.st_mode)) {
		DIR *directory = opendir(path);

		if (!directory) {
			return false;
		}

		struct dirent *entry;

		while ((entry = readdir(directory))) {
			if (0 == strcmp(entry->d_name, ".") || 0 == strcmp(entry->d_name, "..")) {
				continue;
			}

			char *child = (char *) malloc(strlen(path) + strlen(entry->d_name) + 2);
			sprintf(child, "%s/%s", path, entry->d_name);
			bool result = PathDeleteRecursively(child);
			free(child);
			if (!result) return result;
		}

		closedir(directory);
		return 0 == rmdir(path);
	} else if (S_ISREG(s.st_mode) || S_ISLNK(s.st_mode)) {
		return 0 == unlink(path);
	} else {
		return false;
	}
#endif
}

int ExternalPathDeleteRecursively(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	returnValue->i = PathDeleteRecursively(temporary);
	free(temporary);
	return 2;
}

int ExternalPathMove(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 2) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	uint64_t index2 = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index2) return -1;
	HeapEntry *entry2 = &context->heap[index2];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	if (entry2->type == T_EOF) return 2;
	if (entry2->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	char *temporary2 = malloc(entry2->bytes + 1);
	if (!temporary2) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	memcpy(temporary2, entry2->text, entry2->bytes);
	temporary2[entry2->bytes] = 0;
	returnValue->i = rename(temporary, temporary2) == 0;
	free(temporary);
	free(temporary2);
	return 2;
}

int ExternalFileCopy(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 2) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	uint64_t index2 = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index2) return -1;
	HeapEntry *entry2 = &context->heap[index2];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	if (entry2->type == T_EOF) return 2;
	if (entry2->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	char *temporary2 = malloc(entry2->bytes + 1);
	if (!temporary2) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	memcpy(temporary2, entry2->text, entry2->bytes);
	temporary2[entry2->bytes] = 0;
	FILE *f = fopen(temporary, "rb");
	FILE *f2 = fopen(temporary2, "wb");
	free(temporary);
	free(temporary2);
	bool okay = true;

	if (f && f2) {
		char buffer[4096];

		while (true) {
			intptr_t bytesRead = fread(buffer, 1, sizeof(buffer), f);
			if (bytesRead < 0) okay = false;
			if (bytesRead <= 0) break;
			intptr_t bytesWritten = fwrite(buffer, 1, bytesRead, f2);
			if (bytesWritten != bytesRead) okay = false;
		}
	} else okay = false;
	
	if (f && fclose(f)) okay = false;
	if (f2 && fclose(f2)) okay = false;
	returnValue->i = okay;
	return 2;
}

int ExternalSystemGetEnvironmentVariable(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 3;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 3;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	char *data = getenv(temporary);
	size_t length = data ? strlen(data) : 0;
	char *copy = (char *) malloc(length + 1);
	if (length) strcpy(copy, data);
	else *copy = 0;
	index = HeapAllocate(context);
	context->heap[index].type = T_STR;
	context->heap[index].bytes = length;
	context->heap[index].text = copy;
	returnValue->i = index;
	free(temporary);
	return 3;
}

int ExternalSystemSetEnvironmentVariable(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 2) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	uint64_t index2 = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	if (context->heapEntriesAllocated <= index2) return -1;
	HeapEntry *entry = &context->heap[index];
	HeapEntry *entry2 = &context->heap[index2];
	returnValue->i = 0;
	if (entry->type == T_EOF || entry2->type == T_EOF) return 2;
	if (entry2->type != T_STR) return -1;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 3;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	char *temporary2 = malloc(entry2->bytes + 1);
	memcpy(temporary2, entry2->text, entry2->bytes);
	temporary2[entry2->bytes] = 0;
	returnValue->i = setenv(temporary, temporary2, true) == 0;
	free(temporary);
	free(temporary2);
	return 2;
}

int ExternalFileReadAll(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 3;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 3;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	size_t length = 0;
	void *data = FileLoad(temporary, &length);
	index = HeapAllocate(context);
	context->heap[index].type = T_STR;
	context->heap[index].bytes = length;
	context->heap[index].text = data;
	returnValue->i = index;
	free(temporary);
	return 3;
}

int ExternalFileWriteAll(ExecutionContext *context, Value *returnValue) {
	if (context->stackPointer < 2) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	uint64_t index2 = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	if (context->heapEntriesAllocated <= index2) return -1;
	HeapEntry *entry = &context->heap[index];
	HeapEntry *entry2 = &context->heap[index2];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry2->type != T_STR && entry2->type != T_EOF) return -1;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 3;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	FILE *f = fopen(temporary, "wb");

	if (f) {
		if (entry2->type == T_STR) returnValue->i = entry2->bytes == fwrite(entry2->text, 1, entry2->bytes, f);
		if (fclose(f)) returnValue->i = 0;
	}

	free(temporary);
	return 2;
}

int ExternalPathGetDefaultPrefix(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	char *data = (char *) malloc(10000);

	if (!data || data != getcwd(data, 10000)) {
		PrintError4(context, 0, "Could not get the working directory.\n");
		free(data);
		return 0;
	}

	uint64_t index = HeapAllocate(context);
	context->heap[index].type = T_STR;
	context->heap[index].bytes = strlen(data);
	context->heap[index].text = realloc(data, strlen(data) + 1);
	returnValue->i = index;
	return 3;
}

int ExternalPathSetDefaultPrefixToScriptSourceDirectory(ExecutionContext *context, Value *returnValue) {
	(void) context;
	returnValue->i = chdir(scriptSourceDirectory) == 0;
	return 2;
}

int ExternalPersistRead(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;
	if (context->stackPointer < 1) return -1;
	uint64_t index = context->stack[--context->stackPointer].i;
	if (!context->stackIsManaged[context->stackPointer]) return -1;
	if (context->heapEntriesAllocated <= index) return -1;
	HeapEntry *entry = &context->heap[index];
	returnValue->i = 0;
	if (entry->type == T_EOF) return 2;
	if (entry->type != T_STR) return -1;
	char *temporary = malloc(entry->bytes + 1);
	if (!temporary) return 2;
	memcpy(temporary, entry->text, entry->bytes);
	temporary[entry->bytes] = 0;
	free(context->scriptPersistFile);
	context->scriptPersistFile = temporary;
	size_t length = 0;
	uint8_t *data = (uint8_t *) FileLoad(temporary, &length);
	returnValue->i = 1;

	for (uintptr_t i = 0; i < length; ) {
		uint32_t variableNameLength, variableDataLength;
		char variableName[256];
		if (length < sizeof(uint32_t) * 2) break;
		if (i > length - sizeof(uint32_t) * 2) break;
		memcpy(&variableNameLength, &data[i], sizeof(uint32_t)); i += sizeof(uint32_t);
		memcpy(&variableDataLength, &data[i], sizeof(uint32_t)); i += sizeof(uint32_t);
		if (variableNameLength > 256) break;
		if (length < variableNameLength + variableDataLength) break;
		if (i > length - variableNameLength - variableDataLength) break;
		memcpy(variableName, &data[i], variableNameLength); i += variableNameLength;
		uintptr_t k = context->mainModule->globalVariableOffset;
		Scope *scope = context->mainModule->rootNode->scope;

		for (uintptr_t j = 0; j < scope->entryCount; j++) {
			if (scope->entries[j]->token.textBytes == variableNameLength
					&& 0 == MemoryCompare(scope->entries[j]->token.text, variableName, variableNameLength)
					&& scope->entries[j]->type == T_DECLARE
					&& scope->entries[j]->isPersistentVariable) {
				if (scope->entries[j]->expressionType->type == T_STR) {
					// TODO Handling allocation failures.
					context->variables[k].i = HeapAllocate(context);
					context->heap[context->variables[k].i].type = T_STR;
					context->heap[context->variables[k].i].bytes = variableDataLength;
					context->heap[context->variables[k].i].text = AllocateResize(NULL, variableDataLength);
					memcpy(context->heap[context->variables[k].i].text, &data[i], variableDataLength);
				} else if (scope->entries[j]->expressionType->type == T_INT) {
					if (variableDataLength == sizeof(int64_t)) memcpy(&context->variables[k].i, &data[i], sizeof(int64_t));
				} else if (scope->entries[j]->expressionType->type == T_FLOAT) {
					if (variableDataLength == sizeof(double)) memcpy(&context->variables[k].f, &data[i], sizeof(double));
				} else if (scope->entries[j]->expressionType->type == T_BOOL) {
					if (variableDataLength == 1) context->variables[k].i = data[i] == 1;
				} else {
					// TODO What should happen here?
				}

				break;
			}

			if (ScopeIsVariableType(scope->entries[j])) {
				k++;
			}
		}

		i += variableDataLength;
	}

	free(data);
	return 2;
}

int ExternalPersistWrite(ExecutionContext *context, Value *returnValue) {
	(void) returnValue;

	if (!context->scriptPersistFile) {
		// TODO Report the file/line number.
		PrintError3("Attempted to modify a persistent variable before calling PersistRead.\n");
		return 0;
	}

	FILE *f = fopen(context->scriptPersistFile, "wb");

	if (!f) {
		PrintDebug("\033[0;32mWarning: Persistent variables could not written. The file could not be opened.\033[0m\n");
		return 1;
	}

	uintptr_t k = context->mainModule->globalVariableOffset;
	Scope *scope = context->mainModule->rootNode->scope;

	for (uintptr_t j = 0; j < scope->entryCount; j++) {
		if (scope->entries[j]->type == T_DECLARE && scope->entries[j]->isPersistentVariable) {
			uint32_t variableNameLength = scope->entries[j]->token.textBytes;
			fwrite(&variableNameLength, 1, sizeof(uint32_t), f);

			if (scope->entries[j]->expressionType->type == T_STR) {
				HeapEntry *entry = &context->heap[context->variables[k].i];
				uint32_t variableDataLength = entry->type == T_STR ? entry->bytes : 0;
				fwrite(&variableDataLength, 1, sizeof(uint32_t), f);
				fwrite(scope->entries[j]->token.text, 1, variableNameLength, f);
				if (entry->bytes) fwrite(entry->text, 1, variableDataLength, f);
			} else if (scope->entries[j]->expressionType->type == T_INT) {
				uint32_t variableDataLength = sizeof(int64_t);
				fwrite(&variableDataLength, 1, sizeof(uint32_t), f);
				fwrite(scope->entries[j]->token.text, 1, variableNameLength, f);
				fwrite(&context->variables[k].i, 1, sizeof(int64_t), f);
			} else if (scope->entries[j]->expressionType->type == T_FLOAT) {
				uint32_t variableDataLength = sizeof(double);
				fwrite(&variableDataLength, 1, sizeof(uint32_t), f);
				fwrite(scope->entries[j]->token.text, 1, variableNameLength, f);
				fwrite(&context->variables[k].f, 1, sizeof(double), f);
			} else if (scope->entries[j]->expressionType->type == T_BOOL) {
				uint32_t variableDataLength = 1;
				fwrite(&variableDataLength, 1, sizeof(uint32_t), f);
				fwrite(scope->entries[j]->token.text, 1, variableNameLength, f);
				uint8_t b = context->variables[k].i == 1;
				fwrite(&b, 1, sizeof(uint8_t), f);
			} else {
				PrintDebug("\033[0;32mWarning: The persistent variable %.*s could not be written, because it had an unsupported type.\033[0m\n",
						scope->entries[j]->token.textBytes, scope->entries[j]->token.text);
			}
		}

		if (ScopeIsVariableType(scope->entries[j])) {
			k++;
		}
	}

	if (fclose(f)) {
		PrintDebug("\033[0;32mWarning: Persistent variables could not written. The file could not be closed.\033[0m\n");
		return 1;
	}

	return 1;
}

int ExternalConsoleGetLine(ExecutionContext *context, Value *returnValue) {
#ifdef _WIN32
#pragma message ("ExternalConsoleGetLine unimplemented")
	return -1;
#else
	char *line = NULL;
	size_t pos;
	getline(&line, &pos, stdin);
	uintptr_t index = HeapAllocate(context);
	context->heap[index].type = T_STR;
	context->heap[index].bytes = strlen(line) - 1;
	context->heap[index].text = line;
	returnValue->i = index;
	return 3;
#endif
}

int ExternalSystemGetProcessorCount(ExecutionContext *context, Value *returnValue) {
	(void) context;
#ifdef _WIN32
#pragma message ("ExternalSystemGetProcessorCount unimplemented")
	returnValue->i = 1;
#else
	returnValue->i = sysconf(_SC_NPROCESSORS_CONF);
#endif
	if (returnValue->i < 1) returnValue->i = 1;
	if (returnValue->i > 10000) returnValue->i = 1; // Values this large are obviously wrong.
	return 2;
}

void *AllocateFixed(size_t bytes) {
	if (!bytes) {
		return NULL;
	}

	bytes = (bytes + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);

	if (bytes >= fixedAllocationCurrentSize || fixedAllocationCurrentPosition >= fixedAllocationCurrentSize - bytes) {
#if 1
		fixedAllocationCurrentSize = bytes > 1048576 ? bytes : 1048576;
#else
		fixedAllocationCurrentSize = bytes;
#endif
		fixedAllocationCurrentPosition = 0;
		fixedAllocationCurrentBlock = calloc(1, fixedAllocationCurrentSize + sizeof(void *));

		if (!fixedAllocationCurrentBlock) {
			fprintf(stderr, "Internal error: not enough memory to run the script.\n");
			exit(1);
		}

		*(void **) fixedAllocationCurrentBlock = fixedAllocationBlocks;
		fixedAllocationBlocks = (void **) fixedAllocationCurrentBlock;
		fixedAllocationCurrentBlock += sizeof(void *);
	}

	void *p = fixedAllocationCurrentBlock + fixedAllocationCurrentPosition;
	fixedAllocationCurrentPosition += bytes;
	return p;
}

void *AllocateResize(void *old, size_t bytes) {
	if (bytes == 0) {
		free(old);
		return NULL;
	}

	void *p = realloc(old, bytes);

	if (!p && bytes) {
		fprintf(stderr, "Internal error: not enough memory to run the script.\n");
		exit(1);
		// TODO Better error handling.
	}

	return p;
}

int MemoryCompare(const void *a, const void *b, size_t bytes) {
	return memcmp(a, b, bytes);
}

void MemoryCopy(void *a, const void *b, size_t bytes) {
	memcpy(a, b, bytes);
}

size_t PrintIntegerToBuffer(char *buffer, size_t bufferBytes, int64_t i) {
	snprintf(buffer, bufferBytes, "%ld", i);
	return strlen(buffer);
}

size_t PrintFloatToBuffer(char *buffer, size_t bufferBytes, double f) {
	snprintf(buffer, bufferBytes, "%f", f);
	return strlen(buffer);
}

void PrintDebug(const char *format, ...) {
	va_list arguments;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
}

void PrintLine(ImportData *importData, uintptr_t line) {
	uintptr_t position = 0;

	for (uintptr_t i = 1; i < line; i++) {
		while (position < importData->fileDataBytes) {
			if (((char *) importData->fileData)[position] == '\n') {
				position++;
				break;
			}

			position++;
		}
	}

	uintptr_t length = 0;

	for (uintptr_t i = position; i < importData->fileDataBytes; i++) {
		if (((char *) importData->fileData)[i] == '\n') {
			length = i - position;
			break;
		}
	}

	fprintf(stderr, ">> %.*s\n", (int) length, &((char *) importData->fileData)[position]);
}

void PrintError(Tokenizer *tokenizer, const char *format, ...) {
	fprintf(stderr, "\033[0;33mError on line %d of '%s':\033[0m\n", (int) tokenizer->line, tokenizer->module->path);
	va_list arguments;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
	PrintLine(tokenizer->module, tokenizer->line);
}

void PrintError2(Tokenizer *tokenizer, Node *node, const char *format, ...) {
	fprintf(stderr, "\033[0;33mError on line %d of '%s':\033[0m\n", (int) node->token.line, tokenizer->module->path);
	va_list arguments;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
	PrintLine(tokenizer->module, node->token.line);
}

void PrintError3(const char *format, ...) {
	fprintf(stderr, "\033[0;33mGeneral error:\033[0m\n");
	va_list arguments;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
}

void LineNumberLookup(ExecutionContext *context, uint32_t instructionPointer, LineNumber *output) {
	for (uintptr_t i = 0; i < context->functionData->lineNumberCount; i++) {
		if (context->functionData->lineNumbers[i].instructionPointer == instructionPointer) {
			*output = context->functionData->lineNumbers[i];
			return;
		}
	}
}

void PrintError4(ExecutionContext *context, uint32_t instructionPointer, const char *format, ...) {
	LineNumber lineNumber = { 0 };
	LineNumberLookup(context, instructionPointer, &lineNumber);
	fprintf(stderr, "\033[0;33mRuntime error on line %d of '%s'\033[0m:\n", lineNumber.lineNumber, lineNumber.importData->path);
	va_list arguments;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
	PrintLine(lineNumber.importData, lineNumber.lineNumber);

	BackTraceLink *link = context->backTrace;
	fprintf(stderr, "Back trace:\n");
	fprintf(stderr, "\t%s:%d %s %.*s\n", lineNumber.importData->path, lineNumber.lineNumber, lineNumber.function ? "in" : "",
			lineNumber.function ? (int) lineNumber.function->textBytes : 0, lineNumber.function ? lineNumber.function->text : "");

	while (link) {
		LineNumberLookup(context, link->instructionPointer, &lineNumber);
		fprintf(stderr, "\t%s:%d %s %.*s\n", lineNumber.importData->path, lineNumber.lineNumber, lineNumber.function ? "in" : "",
				lineNumber.function ? (int) lineNumber.function->textBytes : 0, lineNumber.function ? lineNumber.function->text : "");
		link = link->previous;
	}
}

void *FileLoad(const char *path, size_t *length) {
	FILE *file = fopen(path, "rb");
	if (!file) return NULL;
	fseek(file, 0, SEEK_END);
	size_t fileSize = ftell(file);
	fseek(file, 0, SEEK_SET);
	char *buffer = (char *) malloc(fileSize + 1);
	buffer[fileSize] = 0;
	fread(buffer, 1, fileSize, file);
	fclose(file);
	if (length) *length = fileSize;
	return buffer;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <path to script> <script options...>\n", argv[0]);
		return 1;
	}

	options = argv + 2;
	optionCount = argc - 2;
	optionsMatched = (bool *) calloc(argc - 2, sizeof(bool));

	scriptSourceDirectory = (char *) malloc(strlen(argv[1]) + 2);
	strcpy(scriptSourceDirectory, argv[1]);
	char *lastSlash = strrchr(scriptSourceDirectory, '/');
	if (lastSlash) *lastSlash = 0;
	else strcpy(scriptSourceDirectory, ".");

	Tokenizer tokenizer = { 0 };
	ImportData importData = { 0 };
	importData.path = argv[1];
	importData.pathBytes = strlen(argv[1]);
	importData.fileData = FileLoad(argv[1], &tokenizer.inputBytes);
	importData.fileDataBytes = tokenizer.inputBytes;
	tokenizer.module = &importData;
	tokenizer.line = 1;
	tokenizer.input = importData.fileData;

	if (!tokenizer.input) {
		fprintf(stderr, "Error: Could not load the input file '%s'.\n", argv[1]);
		return 1;
	}

	FunctionBuilder builder = { 0 };
	ExecutionContext context = { 0 };
	context.functionData = &builder;
	context.mainModule = &importData;

	context.stackEntriesAllocated = sizeof(context.stack) / sizeof(context.stack[0]);
	context.heapEntriesAllocated = 2;
	context.heap = (HeapEntry *) AllocateResize(NULL, sizeof(HeapEntry) * context.heapEntriesAllocated);
	context.heap[0].type = T_EOF;
	context.heap[1].type = T_ERROR;
	context.heap[1].nextUnusedEntry = 0;
	context.heapFirstUnusedEntry = 1;

	int result = ScriptLoad(tokenizer, &context, &importData) ? ScriptExecute(&context, &importData) : 1;
	ScriptFree(&context);

	while (fixedAllocationBlocks) {
		void *block = fixedAllocationBlocks;
		fixedAllocationBlocks = (void **) *fixedAllocationBlocks;
		free(block);
	}

	free(scriptSourceDirectory);
	free(optionsMatched);

	return result;
}