#include "ProcessMitigation.h"


void GetMitigation(HANDLE hProcess, PMITIGATION m)
{
	PROCESS_MITIGATION_DEP_POLICY dep{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessDEPPolicy, &dep, sizeof(dep)))
		m->DEPPolicy = -1;
	else
		m->DEPPolicy = dep.Enable;

	PROCESS_MITIGATION_ASLR_POLICY aslr{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessASLRPolicy, &aslr, sizeof(aslr)))
		m->ASLRPolicy = -1;
	else
		m->ASLRPolicy = aslr.EnableBottomUpRandomization;

	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{ 0 };
	if (!::GetProcessMitigationPolicy(hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)))
		m->ControlFlowGuardPolicy = -1;
	else
		m->ControlFlowGuardPolicy = cfg.EnableControlFlowGuard;
}