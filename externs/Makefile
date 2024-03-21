TARGET = ipfix
SRCDIR = src/$(TARGET)
SOURCES= $(wildcard */*/*.cpp) $(wildcard */*/*.h)
OBJDIR = obj
CXX = g++
CXXFLAGS = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -shared

.PHONY: all clean

all: $(OBJDIR)/$(TARGET).so

# Rule to compile each source file into an object file
$(OBJDIR)/$(TARGET).so: $(SOURCES)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^ -ltins

# Clean rule
clean:
	rm -f $(OBJDIR)/%.so
