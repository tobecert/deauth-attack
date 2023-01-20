all: deauth-attack

deauth-attack: deauth-attack.o
	gcc -o deauth-attack deauth-attack.o -lpcap
deauth-attack.o: main.h main.c
	gcc -c -o deauth-attack.o main.c -lpcap
clean:
	rm -f deauth-attack
	rm -f *.o
