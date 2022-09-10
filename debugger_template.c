#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/personality.h>
#include "linenoise.h"

struct breakpoint  // para poner el breakpoint en una direccion de memoria
{                  // codigos de operacion
    uint64_t addr; // tipo de dato definida en la libreria stdint entero sin signo de 64 bits
    // uint8_t inst_length; //agrego profesor pide longitud de la instruccion en bites para el next
    uint8_t prev_opcode; // tipo de dato definida en la libreria stdint entero sin signo de 8 bits (codigo operacion de 8 bits para hacer backup)
    uint8_t active;      // entero sin signo de 8 bits para avisar que el breakpoint esta activo
};

struct debugee // proceso hijo
{
    char *name; // nombre del programa
    pid_t pid;  // proces id que se asigno
};

struct reg_descriptor // estructura para los registros
{
    int dwarf_r;
    char *name;
};

const int n_registers = 27;

const struct reg_descriptor g_register_descriptors[] = {
    {0, "r15"},
    {1, "r14"},
    {2, "r13"},
    {3, "r12"},
    {4, "rbp"},
    {5, "rbx"},
    {6, "r11"},
    {7, "r10"},
    {8, "r9"},
    {9, "r8"},
    {10, "rax"},
    {11, "rcx"},
    {12, "rdx"},
    {13, "rsi"},
    {14, "rdi"},
    {15, "orig_rax"},
    {16, "rip"},
    {17, "cs"},
    {18, "eflags"},
    {19, "rsp"},
    {20, "ss"},
    {21, "fs_base"},
    {22, "gs_base"},
    {23, "ds"},
    {24, "es"},
    {25, "fs"},
    {26, "gs"},
};

void handle_command(char *);
void fijar_linea_breakpoint(void);

struct debugee *child;            // definicion de variable global que es apuntador a estuctura debugee
struct breakpoint *breakpts[5];   // definicion de variable global que son apuntadores en arreglo de 5 breakpoints a estuctura breakpoint
struct breakpoint *breakauxiliar; // definicion de variable global que es apuntador breakpoint auxiliar a estuctura breakpoint
int bp_index = 0;                 // instanciamos el indexador de breakpoints

int main(int argc, char *argv[]) // funcion main solo se cambia para agregar varios break en vez de 1 solo break con arreglo de breakpts
{
    if (argc < 2)
    {
        printf("Nombre del programa no especificado");
        return -1;
    }
    child = (struct debugee *)malloc(sizeof(struct debugee)); // inicializo la estructura debugee con malloc

    // para inicializar varios breakpoints y no uno solo en el main
    int s;
    for (s = 0; s < 5; s++)
    {
        // breakpt  = (struct breakpoint*)malloc(sizeof(struct breakpoint));
        // breakpt->active = 0;
        breakpts[s] = (struct breakpoint *)malloc(sizeof(struct breakpoint)); // inicializo la estructura breakpoint con malloc
        breakpts[s]->active = 0;                                              // aseguro que estructura breakpoints inactivo
    }

    breakauxiliar = (struct breakpoint *)malloc(sizeof(struct breakpoint)); // breakpoint auxiliar

    child->name = argv[1]; // se manda el nombre del programa a debuguear
    child->pid = fork();   // para crear un subproceso hijo que es copia del proceso
                         // lineas que solo se ejecutan en el proceso hijo
    if (child->pid == 0)
    {
        personality(ADDR_NO_RANDOMIZE);        // desactivar el randomize para poder ver las direcciones de memoria para poder usarlas
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // se le indica sobre cual proceso se le hara el rastreo
        execl(child->name, child->name, NULL); // proceso hijo con codigo fuente distinto
    }
    else if (child->pid >= 1) // lineas que solo  se ejecuta en el proceso padre
    {
        int status;
        int options = 0;
        waitpid(child->pid, &status, options); // Monitorea el proceso que se le manda como primer paramentro, en el segundo paramentro se almacena como int en el estado del proceso
        // uso de la libreria linenoise
        char *line = NULL;
        while ((line = linenoise("minidbg> ")) != NULL)
        {
            handle_command(line); // llamado a la funcion que usa comandos que se introducen para realizar el debug

            linenoiseHistoryAdd(line);
            linenoiseFree(line); // hay que escribir ctrl + d para terminar los procesos
        }
    }

    free(child); // libero estructura debugee
    // para liberar el arreglo de estructura breakpoints inicializados anteriormente
    int i;
    for (i = 0; i < 5; i++)
    {
        free(breakpts[i]); // free(breakpt);
    }

    return 0;
}

void fijar_linea_breakpoint() // funcion para fijar el break en una linea
{
    int i;
    uint64_t last_line;
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
    // se toma el rip para saber donde se esta posicionado, se reccore buscando break activo y que coincida con la linea en posicion, funciona por que el codigo de la linea 139 mide 1 bite
    last_line = regs.rip - 1;
    for (i = 0; i < bp_index; i++)
    {
        // se toma los datos del breakpoint y se le asigna el codigo de operacion guardado anteriormente y se ejecuta una instruccion
        struct breakpoint *breakpt;
        breakpt = breakpts[i];
        if (breakpt->active == 1 && breakpt->addr == last_line)
        {
            regs.rip = last_line;
            ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
            uint64_t data_with_breakpoint = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
            uint64_t previous_data = ((data_with_breakpoint & ~0xff) | breakpt->prev_opcode);
            ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, previous_data); // reestablecemos el breakpoint
            breakauxiliar->addr = breakpt->addr;                               // guardo direccion en breakpoint auxiliar
        }
    }
}

void handle_command(char *line) // se hace una especie de case con el linenoise para cada comando
{

    if (!strncmp(line, "break", 5)) // creacion del comando breakpoint
    {
        printf("indice: %d\n", bp_index);
        if (bp_index < 5) // mientras el indice sea menor a 5
        {                 // If you want to enable a breakpoint (in a provided adress, for example 0x555555554655), you must to use the following CALL
            // breakpt->addr =  ((uint64_t)strtol("0x555555554655", NULL, 0));
            breakpts[bp_index]->addr = ((uint64_t)strtol(line + 6, NULL, 0));                    //
            uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakpts[bp_index]->addr, NULL); // lee una palabra, que contiene la instruccion en la direccion de memoria pasada por paramentro
            breakpts[bp_index]->prev_opcode = (uint8_t)(data & 0xff);                            // retorna los ultimos 8 bits de la palabra data
            uint64_t int3 = 0xcc;                                                                // codigo operacion para poner breakpoint, mide 1 bite para que funcione el rip en -1 y solo incrementa en 1
            uint64_t data_with_int3 = ((data & ~0xff) | int3);                                   // reemplaza los ultimos digitos de la instruccion con los bits que causan una interrupcion

            ptrace(PTRACE_POKEDATA, child->pid, breakpts[bp_index]->addr, data_with_int3); // copia lo enviado en el data a la direccion que se manda como parametro
            breakpts[bp_index]->active = 1;                                                // cambia el estado del breakpoint indizado
            bp_index++;                                                                    // aumenta la indizacion en 1 para que el otro slot del arreglo quede disponible
        }
    }

    else if (!strncmp(line, "continue", 8)) // Si desea continuar con la ejecución del programa a debuguear (compara si son iguales)
    {
        fijar_linea_breakpoint();                    // se llama esta funcion para cuando se tiene el breakpoint fijado y se quiere continuar
        ptrace(PTRACE_CONT, child->pid, NULL, NULL); // se continua con lo enviado en data (inicia el continue)
        int status;
        int options = 0;
        waitpid(child->pid, &status, options); // monitorea el proceso que se le manda como primer parametro, en el segundo paramentro se almacena como int en el estado del proceso (acabo el continue)
        // para desabilitar un breakpoint
        uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakauxiliar->addr, NULL); // reestablesco el breakpoint con la direccion guardada en breakpoint auxiliar
        uint64_t int3 = 0xcc;                                                           // codigo que genera una interrupcion
        uint64_t data_with_int3 = ((data & ~0xff) | int3);                              // reemplaza los ultimos digitos de la instruccion con los bits que causan una interrupcion
        ptrace(PTRACE_POKEDATA, child->pid, breakauxiliar->addr, data_with_int3);       // copia lo enviado en el data a la direeicon que se manda como paramentro
    }

    else if (!strncmp(line, "next", 4))
    {
        // To execute a singe step
        ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);
    }

    else if (!strncmp(line, "register write rip", 18))
    {
        struct user_regs_struct regs;
        uint64_t register_address = ((uint64_t)strtol(line + 19, NULL, 0));
        ptrace(PTRACE_GETREGS, child->pid, NULL, &regs); // hace una copia en &regs de los registros del proceso en el que nos encontramos
        regs.rip = register_address;                     // se le asigna al rip la direccion de registro
        ptrace(PTRACE_SETREGS, child->pid, NULL, &regs); // se actualiza &regs
    }
    else
    {
        printf("Comando desconocido, escriba continue por favor en minusculas ó Ctrl+d para salir \n");
    } // en caso de meter un comando diferente a "continue"
}

// At this point you must to implement all the logic to manage the inputs of the program:
// continue -> To continue the execution of the program
// next -> To go step by step
// register write/read <reg_name> <value>(when write format 0xVALUE) -> To read/write the value of a register (see the global variable g_register_descriptors)
// break <0xVALUE> (Hexadecimal) -> To put a breakpoint in an adress

// The following lines show a basic example of how to use the PTRACE API

// Read the registers

/*struct user_regs_struct regs;
uint64_t *register_address;
ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);*/

// Write the registers -> If you want to change a register, you must to read them first using the previous call, modify the struct user_regs_struct
//(the register that you want to change) and then use the following call

/*ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);*/

// To disable a breakpoint
// data = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
// uint64_t restored_data = ((data & ~0xff) | breakpt->prev_opcode);
// ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, restored_data);
// breakpt->active = 0;

// To read the value in a memory adress
// uint64_t value_in_memory = (uint64_t)ptrace(PTRACE_PEEKDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), NULL);

// To write a value in an adress
// ptrace(PTRACE_POKEDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), (uint64_t)strtol("0x555555554655", NULL, 0));
// To write a value in an adress
// ptrace(PTRACE_POKEDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), (uint64_t)strtol("0x555555554655", NULL, 0));
