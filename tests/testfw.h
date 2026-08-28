/*
 * testfw.h - minimal dependency-free test framework for the test suite.
 *
 * Usage: TF_INIT(filter); TF_GROUP("name"); CHECK(cond, "label");
 * A group filter (substring match) can be passed to the binary; groups
 * that do not match report nothing.  tf_summary() returns non-zero when
 * any check failed.
 */
#ifndef TESTFW_H
#define TESTFW_H

#include <windows.h>
#include <stdio.h>
#include <string.h>

static int tf_pass, tf_fail, tf_skip;
static const char *tf_group = "(none)";
static const char *tf_filter = NULL;

static BOOL tf_active(const char *group)
{
    return tf_filter == NULL || strstr(group, tf_filter) != NULL;
}

#define TF_INIT(filter_arg) tf_filter = (filter_arg)
#define TF_GROUP(name) tf_group = (name)

#define CHECK(cond, name)                                                    \
    do {                                                                     \
        if (!tf_active(tf_group)) break;                                     \
        if (cond) {                                                          \
            tf_pass++; printf("[PASS] %-9s %s\n", tf_group, name);           \
        } else {                                                             \
            tf_fail++; printf("[FAIL] %-9s %s (line %d)\n", tf_group, name,  \
                              __LINE__);                                     \
        }                                                                    \
    } while (0)

#define SKIP_TEST(name, why)                                                 \
    do {                                                                     \
        if (!tf_active(tf_group)) break;                                     \
        tf_skip++; printf("[SKIP] %-9s %s (%s)\n", tf_group, name, why);     \
    } while (0)

static int tf_summary(void)
{
    printf("== total: %d passed, %d failed, %d skipped ==\n",
           tf_pass, tf_fail, tf_skip);
    return tf_fail ? 1 : 0;
}

/* Process token elevation - used to pick expectations for admin-locked
 * files (restrictive DACL allows SYSTEM + Administrators only). */
static BOOL tf_is_elevated(void)
{
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION el = { 0 };
        DWORD got = 0;
        if (GetTokenInformation(token, TokenElevation, &el, sizeof(el), &got))
            elevated = el.TokenIsElevated != 0;
        CloseHandle(token);
    }
    return elevated;
}

#endif /* TESTFW_H */
