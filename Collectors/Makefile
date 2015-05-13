PROJECT =  collectors
HEADERS =  $(PROJECT).h
OBJ 	=  src/collectors.o src/connections.o

C99	=  cc -std=c99
CFLAGS	=  -Wall -Wno-deprecated-declarations -pedantic -Werror
LIBS	= -lssl -lcrypto 

$(PROJECT) : $(OBJ)
	$(C99) $(CFLAGS) -o  $(PROJECT) $(OBJ) $(LIBS) -lm

%.o : %.c $(HEADERS)
	$(C99) $(CFLAGS) -c $<

clean:
	rm -f $(PROJECT) $(OBJ) 

