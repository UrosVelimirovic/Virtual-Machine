all: clean mini_hypervisor guest1.img guest2.img 

mini_hypervisor: mini_hypervisor.cpp 
	gcc mini_hypervisor.cpp -o mini_hypervisor -pthread -lstdc++ -g

guest1.img: guest1.o
	ld -T guest1.ld guest1.o -o guest1.img

guest1.o: guest1.cpp
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

guest2.img: guest2.o
	ld -T guest2.ld guest2.o -o guest2.img

guest2.o: guest2.cpp
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

clean:
	rm -f mini_hypervisor guest1.o guest1.img guest2.o guest2.img 


