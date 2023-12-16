pack:
	-rm -f ../src.zip
	zip -r ./src.zip ./tests/*.c ./tests/*.h ./tests/*.sh ./tests/Makefile ./src/*.c ./src/*.h ./src/Makefile ./src/*.md