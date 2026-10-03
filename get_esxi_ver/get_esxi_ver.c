/*
    (c) Maxim Suhanov, 2026
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <cpuid.h>
#include <sys/io.h>

#define VMWARE_CPUID "VMwareVMware"

#define BDOOR_MAGIC 0x564D5868u
#define BDOOR_PORT 0x5658u

#define BDOOR_CMD_GETVERSION 10u

// Supported on ESXi 7.0.3+ only...
#define BDOOR_CMD_GETBUILDNUM 100u

// Is the I/O port access available on this machine? If not, use hypercalls (VMCALL/VMMCALL).
static int use_io_port;

// Is the VMCALL instruction supported on this machine? If not, use VMMCALL.
static int use_vmcall;

// Function to communicate via the legacy I/O port (used by default).
static uint32_t call_io_backdoor(const uint16_t cmd, const char reg_to_ret)
{
	uint32_t eax = BDOOR_MAGIC;
	uint32_t edx = BDOOR_PORT;
	uint32_t ecx = cmd;
	uint32_t ebx = 0, esi = 0, edi = 0;

	__asm__ __volatile__("inl %%dx, %%eax"
		: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx), "=S"(esi), "=D"(edi)
		: "a"(eax), "b"(ebx), "c"(ecx), "d"(edx), "S"(esi), "D"(edi)
		: "memory", "cc");

	switch (reg_to_ret)
	{
		case 'a':
			return eax;
		case 'b':
			return ebx;
		case 'c':
			return ecx;
		case 'd':
			return edx;
		case 'S':
			return esi;
		case 'D':
			return edi;
	}

	// UNREACHABLE
	return 0xBAADF00Du;
}

// Function to communicate via VMCALL/VMMCALL (used as a fallback when no I/O port access is available).
static uint32_t call_hc_backdoor(const uint16_t cmd, const char reg_to_ret)
{
	uint32_t eax = BDOOR_MAGIC;
	uint32_t edx = BDOOR_PORT;
	uint32_t ecx = cmd;
	uint32_t ebx = 0, esi = 0, edi = 0;

	if (use_vmcall)
		__asm__ __volatile__("vmcall"
			: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx), "=S"(esi), "=D"(edi)
			: "a"(eax), "b"(ebx), "c"(ecx), "d"(edx), "S"(esi), "D"(edi)
			: "memory", "cc");
	else
		__asm__ __volatile__("vmmcall"
			: "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx), "=S"(esi), "=D"(edi)
			: "a"(eax), "b"(ebx), "c"(ecx), "d"(edx), "S"(esi), "D"(edi)
			: "memory", "cc");

	switch (reg_to_ret)
	{
		case 'a':
			return eax;
		case 'b':
			return ebx;
		case 'c':
			return ecx;
		case 'd':
			return edx;
		case 'S':
			return esi;
		case 'D':
			return edi;
	}

	// UNREACHABLE
	return 0xBAADF00Du;
}

// Wrap both backdoor implementations into a single function.
static uint32_t call_backdoor(const uint16_t cmd, const char reg_to_ret)
{
	if (use_io_port)
		return call_io_backdoor(cmd, reg_to_ret);

	return call_hc_backdoor(cmd, reg_to_ret);
}

int main(int argc, char **argv)
{
	uint32_t eax, ebx, ecx, edx;

	__cpuid(1, eax, ebx, ecx, edx); // Request the feature information.

	if ((ecx & 0x80000000u) == 0) // Check the hypervisor bit.
	{
		printf("No hypervisor detected via CPUID!\n");
		return 1;
	}

	__cpuid(0x40000000u, eax, ebx, ecx, edx); // Request the hypervisor level 0 leave.

	char hyper_sig[12];
	uint32_t max_leave;

	memcpy(hyper_sig, &ebx, 4); // Copy the hypervisor's vendor string.
	memcpy(hyper_sig + 4, &ecx, 4);
	memcpy(hyper_sig + 8, &edx, 4);
	max_leave = eax; // Copy the maximum leave available.

	if (memcmp(hyper_sig, VMWARE_CPUID, 12) != 0)
	{
		printf("Hypervisor detected but it is not VMware!\n");
		return 1;
	}

	// We are running inside a VMware hypervisor like Workstation or ESX/ESXi...

	use_io_port = 1;
	if (iopl(3) != 0)
	{
		// This call could fail due to the kernel lockdown feature (enabled when the Secure Boot is on).
		// Actually, this is not "falling back", this is close to "upgrading", but our default choice is the legacy I/O port...
		printf("Cannot change I/O privilege level! Falling back to hypercalls...\n");
		use_io_port = 0;

		// Check if hypercalls to the backdoor are supported...
		if (max_leave >= 0x40000010u)
		{
			ecx = 0;
			__cpuid(0x40000010u, eax, ebx, ecx, edx); // Request the VMware features.
			if ((ecx & 1) > 0)
			{
				// VMMCALL is supported! Use it.
				use_vmcall = 0;
			}
			else if ((ecx & 2) > 0)
			{
				// VMCALL is supported! Use it.
				use_vmcall = 1;
			}
			else
			{
				printf("Hypercalls are not supported! Failing...\n");
				return 2;
			}
		}
		else
		{
			printf("VMware features are not reported! Failing...\n");
			return 2;
		}
	}

	printf("VMware hypervisor detected!\n");

	uint32_t backdoor_signature = 0;
	backdoor_signature = call_backdoor(BDOOR_CMD_GETVERSION, 'b');
	if (backdoor_signature != BDOOR_MAGIC)
	{
		printf("VMware backdoor is not reachable!\n");
		return 2;
	}

	uint32_t product_type = 0, product_build = 0;

	product_type = call_backdoor(BDOOR_CMD_GETVERSION, 'c');
	printf("Hypervisor type (via BDOOR_CMD_GETVERSION): %" PRIu32 " (2 - ESX/ESXi, 4 - Workstation)\n", product_type);

	product_build = call_backdoor(BDOOR_CMD_GETBUILDNUM, 'a');
	if (product_build != 0xFFFFFFFFu)
	{
		printf("Hypervisor build (via BDOOR_CMD_GETBUILDNUM): %" PRIu32 "\n", product_build);
	}

	printf("Done!\n");
	return 0;
}

