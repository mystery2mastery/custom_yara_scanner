#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara.h>

#define MAX_RULES 100

void compile_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data)
{
    const char* level = (error_level == YARA_ERROR_LEVEL_ERROR) ? "ERROR" : "WARNING";
    fprintf(stderr, "%s in %s@%d - %s\n", level, file_name, line_number, message);
}

typedef struct {
    const char* rule_identifier;
    int match_count;
    const char* file_name;
} Rule_Data;

typedef struct {
    Rule_Data rules[MAX_RULES];
    int rule_count;
} User_Data;

/*
The callback function will be called once for each rule with either a CALLBACK_MSG_RULE_MATCHING or CALLBACK_MSG_RULE_NOT_MATCHING message, 
depending if the rule is matching or not. In both cases a pointer to the YR_RULE structure associated with the rule is passed in the message_data argument.
You just need to perform a typecast from void* to YR_RULE* to access the structure.
*/
int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    User_Data* data = (User_Data*)user_data;
    //YR_MATCHES* mymatches = context->matches;
    switch (message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
    {
        YR_RULE* rule = (YR_RULE*)message_data;

        //YR_MATCHES* matches = &context->matches[string->idx];
       // printf("count: %d\n", context->matches[0].count);
       // printf("count: %d\n", context->matches[1].count);
       // printf("count: %d\n", context->matches[2].count);

       // printf("No. of matches: %d\n", mymatches->count);
        printf("Rule Matching: %s\n", rule->identifier);




        //printf("Rule '%s' matched on '%s' %d times:\n", rule->identifier, data->rules[rule_index].file_name, data->rules[rule_index].match_count);

        YR_STRING* string;
        YR_MATCH* match;
        
        //int strcount = 0;

        yr_rule_strings_foreach(rule, string) {
            //printf("No. of matches: %d\n", context->matches->count);
            printf("string [%d]: %s\n",string->idx, string->identifier);
            printf("No. of matches: %d\n", context->matches[string->idx].count);
            yr_string_matches_foreach(context, string, match) {
                printf("Offset %llu (%d bytes): %s\n", match->base + match->offset, (int)match->match_length, match->data);
                
                //strcount++;
            }
        }
        //printf("str count: %d\n", strcount);




        break;
    }
    case CALLBACK_MSG_RULE_NOT_MATCHING:
    {
        YR_RULE* rule = (YR_RULE*)message_data;
        printf("Rule not matching: %s\n", rule->identifier);
        break;
    }
    case CALLBACK_MSG_SCAN_FINISHED:
        printf("Scan finished.\n");
        break;
    case CALLBACK_MSG_IMPORT_MODULE:
    {
        YR_MODULE_IMPORT* moduleImport = (YR_MODULE_IMPORT*)message_data;
        printf("Import module.\n");
        break;
    }
    case CALLBACK_MSG_MODULE_IMPORTED:
    {
        YR_OBJECT_STRUCTURE* moduleObject = (YR_OBJECT_STRUCTURE*)message_data;
        printf("Module imported.\n");
        break;
    }
    case CALLBACK_MSG_TOO_MANY_MATCHES:
    {
        YR_STRING* tooMany = (YR_STRING*)message_data;
        printf("Too many matches.\n");
        break;
    }
    case CALLBACK_MSG_CONSOLE_LOG:
    {
        char* consoleMsg = (char*)message_data;
        printf("Console log: %s\n", consoleMsg);
        break;
    }
    default:
        printf("Unknown message: %d\n", message);
        break;
    }
    return CALLBACK_CONTINUE;
}

void initialize_yara() {
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize YARA.\n");
        exit(EXIT_FAILURE);
    }
    printf("Yara initialization successful\n");
}

void finalize_yara() {
    yr_finalize();
}

void compile_and_scan(const char* file_name) {
    YR_COMPILER* compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to create YARA compiler.\n");
        exit(EXIT_FAILURE);
    }
    printf("Yara rule compiler creation successful\n");

    yr_compiler_set_callback(compiler, (YR_COMPILER_CALLBACK_FUNC)compile_callback, NULL);

    const char* rules =
        "rule test_rule1 { strings: $a = \"Hello\" $b = \"you\" condition: $a and $b}\n"
        "rule test_rule2 { strings: $a = \"ll\" condition: $a}";

    if (yr_compiler_add_string(compiler, rules, NULL) != 0) {
        fprintf(stderr, "Failed to compile YARA rule.\n");
        yr_compiler_destroy(compiler);
        exit(EXIT_FAILURE);
    }
    printf("Yara rule addition successful\n");

    YR_RULES* compiled_rules = NULL;
    if (yr_compiler_get_rules(compiler, &compiled_rules) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get compiled rules.\n");
        yr_compiler_destroy(compiler);
        exit(EXIT_FAILURE);
    }
    printf("Yara rules compilation successful\n");

    yr_compiler_destroy(compiler);

    User_Data user_data = { 0 };
    for (int i = 0; i < MAX_RULES; i++) {
        user_data.rules[i].file_name = file_name;
    }

    if (yr_rules_scan_file(compiled_rules, file_name, 0, (YR_CALLBACK_FUNC)scan_callback, &user_data, 0) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to scan file.\n");
    }

    yr_rules_destroy(compiled_rules);
}

int main() {
    initialize_yara();
    compile_and_scan("C:\\Users\\ElNino\\Desktop\\test.txt");
    finalize_yara();
    return 0;
}
