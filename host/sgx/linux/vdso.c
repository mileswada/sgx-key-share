// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../vdso.h"
#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgx/ecall_context.h>
#include <openenclave/internal/trace.h>
#include <sys/auxv.h>
#include "../asmdefs.h"
#include "../enclave.h"
#include "../exception.h"
#include "sgx.h" // Linux kernel header

extern bool oe_is_avx_enabled;

static elf64_sym_t _sgx_enter_enclave_sym;
static vdso_sgx_enter_enclave_t _vdso_sgx_enter_enclave;

oe_result_t oe_sgx_initialize_vdso(void)
{
    oe_result_t result = OE_NOT_FOUND;
    void* sgx_vdso_base = (void*)getauxval(AT_SYSINFO_EHDR);

    if (!sgx_vdso_base)
        goto done;

    if (elf64_find_dynamic_symbol_by_name_with_header(
            (const elf64_ehdr_t*)sgx_vdso_base,
            "__vdso_sgx_enter_enclave",
            &_sgx_enter_enclave_sym) != 0)
        goto done;

    _vdso_sgx_enter_enclave = (vdso_sgx_enter_enclave_t)(
        (uint64_t)sgx_vdso_base + _sgx_enter_enclave_sym.st_value);

    result = OE_OK;

done:
    if (result == OE_OK)
        OE_TRACE_INFO("vDSO symbols found. Opt into oe_vdso_enter.");
    else
        OE_TRACE_INFO("vDSO symbols not found. Fallback to regular oe_enter "
                      "implementation.");

    return result;
}

typedef struct _vdso_args
{
    uint64_t rdi;
    uint64_t rsi;
} vdso_args_t;

static int oe_vdso_user_handler(
    long rdi,
    long rsi,
    long rdx,
    long rsp,
    long r8,
    long r9,
    struct sgx_enclave_run* run)
{
    uint64_t arg1 = (uint64_t)rdi;
    uint64_t arg2 = (uint64_t)rsi;
    vdso_args_t* return_args = NULL;
    int result = 0;

    OE_UNUSED(rdx);
    OE_UNUSED(rsp);
    OE_UNUSED(r8);
    OE_UNUSED(r9);

    if (!run)
    {
        result = -1;
        goto done;
    }

    return_args = (vdso_args_t*)run->user_data;

    switch (run->function)
    {
        case ENCLU_EENTER:
            /* Unexpected case (e.g., the enclave loses EPC context
             * because of power events). Return failing value. */
            result = -1;
            break;
        case ENCLU_EEXIT:
        {
            /* Regular exit (the enclave finishes an ECALL or makes an
             * OCALL). Return zero.
             * Note that an alternative implementation is returning
             * ENCLU_EENTER. However, doing so requires setting up
             * the input parameters into corresponding registers (e.g.,
             * rdi, rsi, and rdx) and ensuring the compiler to preserve
             * these registers until the function returns. Instead,
             * we return zero to avoid dealing with such complexities
             * and also to use similar implementation as regular enter. */
            return_args->rdi = arg1;
            return_args->rsi = arg2;
            result = 0;
            break;
        }
        case ENCLU_ERESUME:
        {
            /* Hardware exceptions occur */

            oe_host_exception_context_t host_context = {0};

            host_context.rax = ENCLU_ERESUME;
            host_context.rbx = run->tcs;

            /* AEP is assigned by vDSO implementation */

            oe_host_handle_exception(&host_context);

            result = ENCLU_ERESUME;
            break;
        }
    }

done:
    /* If the result <= 0, the value will be forwared as the return
     * value of _vdso_sgx_enter_enclave. Otherwise, _vdso_sgx_enter_enclave
     * will invoke the ENCLU[result] instead of returning to the caller. */
    return result;
}

/* The function should never be inline to preserve the stack frame. */
OE_NEVER_INLINE
oe_result_t oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    oe_ecall_context_t ecall_context = {0};
    oe_result_t result = OE_UNEXPECTED;
    struct sgx_enclave_run run = {0};
    vdso_args_t return_args = {0};
    int return_value = 0;
    uint32_t mxcsr = 0;
    uint16_t fcw = 0;

    oe_setup_ecall_context(&ecall_context);

    run.tcs = (uint64_t)tcs;
    run.user_handler = (uint64_t)oe_vdso_user_handler;
    run.user_data = (uint64_t)&return_args;

    while (1)
    {
        /* Compiler will usually handle this on exiting a function that uses
         * AVX, but we need to avoid the AVX-SSE transition penalty here
         * manually as part of the transition to enclave. See
         * https://software.intel.com/content/www/us/en/develop/articles
         * /avoiding-avx-sse-transition-penalties.html */
        if (oe_is_avx_enabled)
            OE_VZEROUPPER;

        /* The __vdso_sgx_enter_enclave vDSO API does not ensure full
         * compilance with the x86-64 ABI except for general-purpose
         * registers, EFLAGS.DF, and RSP alignment. We save and restore
         * MXCSR and x87 control word before and after the call (same as
         * regular oe_enter implementation) */

        asm volatile("stmxcsr %[mxcsr] \n\t" // Save MXCSR
                     "fstcw %[fcw] \n\t"     // Save x87 control word
                     :
                     : [fcw] "m"(fcw), [mxcsr] "m"(mxcsr)
                     :);

        return_value = (_vdso_sgx_enter_enclave)(
            arg1,
            arg2,
            (uint64_t)&ecall_context,
            ENCLU_EENTER,
            0 /* r8 */,
            0 /* r9 */,
            &run);

        if (return_value < 0)
            OE_RAISE(OE_FAILURE);

        asm volatile("fldcw %[fcw] \n\t"     // Restore x87 control word
                     "ldmxcsr %[mxcsr] \n\t" // Restore MXCSR
                     :
                     : [fcw] "m"(fcw), [mxcsr] "m"(mxcsr)
                     :);

        /* Update arg1 and arg2 with outputs returned by the enclave */
        arg1 = return_args.rdi;
        arg2 = return_args.rsi;

        /* Make an OCALL if needed */
        oe_code_t code = oe_get_code_from_call_arg1(arg1);
        if (code == OE_CODE_OCALL)
        {
            __oe_host_stack_bridge(
                arg1, arg2, &arg1, &arg2, tcs, enclave, &ecall_context);
        }
        else
            break;
    }

    *arg3 = return_args.rdi;
    *arg4 = return_args.rsi;

    result = OE_OK;

done:
    return result;
}
