CFLAGS = -Wall -fPIC -shared -rdynamic
ARCH = linux
LIBS = -lstdc++
JAVA_HOME = /usr/java/j2sdk

all: libpamcalls.so

clean:
	@rm -f com_blueprintit_security_pam_Pam.h
	@rm -f *~ *.so *.o

libpamcalls.so: com_blueprintit_security_pam_Pam.h NativePam.cpp pamcalls.cpp
	$(CC) $(CFLAGS) $(LIBS) -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/$(ARCH) NativePam.cpp -o libpamcalls.so

com_blueprintit_security_pam_Pam.h: ../classes/com/blueprintit/security/pam/Pam.class
	@rm -f com_blueprintit_security_pam_Pam.h
	cd ../classes; javah -d ../native com.blueprintit.security.pam.Pam
