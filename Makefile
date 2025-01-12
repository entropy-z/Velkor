
agent-x64:
	cmake -S Agent -B Agent/Build -D ARCH=64 -D DEBUG=on
	cmake --build Agent/Build
	python3 Scripts/Extract.py -f Bin/Velkor.x64.exe -o Bin/Velkor.x64.bin
	xxd -i Bin/Velkor.x64.bin > Loader/Include/VelkorShell.h

agent-x86:
	cmake -S Agent -B Agent/Build -D ARCH=86 -D DEBUG=on
	cmake --build Agent/Build -v
	python3 Scripts/Extract.py -f Bin/Velkor.x64.exe -o Bin/Velkor.x64.bin
	xxd -i Bin/Velkor.x64.bin > Loader/Include/VelkorShell.h

loader-x64:
	cmake -S Loader -B Loader/Build -D MAIN=exe -D ARCH=64 
	cmake --build Loader/Build -v
	
loader-x86:
	cmake -S Loader -B Loader/Build -D MAIN=exe -D ARCH=64
	cmake --build Loader/Build

# Clean up
clean:
	rm -rf Loader/Build/*
	rm -rf Agent/Build/*
	rm -rf Bin/*
