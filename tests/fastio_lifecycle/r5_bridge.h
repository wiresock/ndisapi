#pragma once
#ifdef __cplusplus
extern "C" {
#endif
void R5DriverInit(void);
void* R5DriverOpen(void);
int R5DriverClose(void*);
long R5DriverRegister(void*,void*,unsigned long,int);
long R5Sections(void);
long R5Mdls(void);
long R5Locked(void);
long R5Clients(void);
long R5OwnedInRange(void*,size_t);
void R5FailRegistration(int);
#ifdef __cplusplus
}
#endif
