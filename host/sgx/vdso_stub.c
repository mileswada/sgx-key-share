// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/trace.h>
#include "vdso.h"

/* Forward declarations */
oe_result_t _oe_sgx_initialize_vdso(void);

oe_result_t _oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave);

/* Weak aliases of functions to prevent missing symbols on
 * Windows where vDSO is not supported. The weak symbol will be
 * substituted by the strong version on Linux with vDSO support. */
oe_result_t _oe_sgx_initialize_vdso(void)
{
    OE_TRACE_INFO("vDSO not supported in the current Linux Kernel");
    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_sgx_initialize_vdso, oe_sgx_initialize_vdso);

oe_result_t _oe_vdso_enter(
    void* tcs,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4,
    oe_enclave_t* enclave)
{
    OE_UNUSED(tcs);
    OE_UNUSED(arg1);
    OE_UNUSED(arg2);
    OE_UNUSED(arg3);
    OE_UNUSED(arg4);
    OE_UNUSED(enclave);

    return OE_UNSUPPORTED;
}
OE_WEAK_ALIAS(_oe_vdso_enter, oe_vdso_enter);
