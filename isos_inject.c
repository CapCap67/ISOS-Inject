#include <argp.h>
#include <err.h>
#include <libelf.h>
#include <stdbool.h>
#include <sysexits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define ELF_INIT_FAILED -1
#define ELF_BEGIN_FAILED -2
#define ELF_GETEHDR_FAILED -3
#define ELF_GETPHDRNUM_FAILED -4
#define ELF_GETPHDR_FAILED -5
#define ELF_GETSHDRIDX_FAILED -6
#define ELF_GETSHDR_FAILED -7
#define ELF_STRPTR_FAILED -8
#define ELF_FLAGSHDR_FAILED -9

#define OFFSET_GOT_FCT 544

/* compilation steps to pass:
	clang-12 -fsyntax-only -Wall -Wextra -Wuninitialized -Wpointer-arith -Wcast-qual -Wcast-align isos_inject.c
	gcc-10 -O2 -Warray-bounds -Wsequence-point -Walloc-zero -Wnull-dereference -Wpointer-arith -Wcast-qual -Wcast-align=strict isos_inject.c -lelf
	gcc-10 -fanalyzer -Wanalyzer-too-complex isos_inject.c -lelf
	clang-tidy
	analyse
*/

static char args_doc[] = "-e elf_file -c code_to_inject [-s sec_name] -b base_addr [-m modify_entry]";

static char doc[] = "Isos_Inject -- a program to inject elf exec";

struct args {
        char *elf_file;
        char *bin_code_file;
        char *section_name;
        char *base_addr;
        bool modify_entry;
};

static struct argp_option options[] = {
  	{"elf_file", 	     	'e', "ELF_FILE", 0, "The elf file that will be analyzed.", 0},
  	{"bin_code", 		'c', "BIN_CODE", 0,  "A binary file that contain the machine code to be injected.", 0},
  	{"sect_name",   	's', "SEC_NAME", 0, "The name of the newly created section.", 0},
  	{"base_addr",   	'b', "BASE_ADDR", 0, "The base address of the injected code.", 0},
	{"entry_point",		'm', "MODIF_ENTRY", 0, "A Boolean that indicates whether the entry function should be modified or not", 0},
	{ 0 }
};


/* Parse the option of argv */
static error_t option_parser (int key, char *arg, struct argp_state *state) {
	struct args *args = state->input;
	switch(key) {
	case 'e':
		args->elf_file = arg;
		break;
	case 'c':
                args->bin_code_file = arg;
                break;
	case 's':
		if (strlen(arg) <= strlen(".note.ABI-tag"))
	                args->section_name = arg;
		else
			printf("WARNING : Given name is too big. Default section name used.\n");
                break;
	case 'b':
                args->base_addr = arg;
                break;
	case 'm':
                args->modify_entry = arg;
                break;
	case ARGP_KEY_ARG:
        	argp_usage(state);
      		break;
	case ARGP_KEY_END:
		if (!args->elf_file || !args->bin_code_file || !args->base_addr ||
		access(args->elf_file, R_OK | W_OK) == -1 ||
		access(args->bin_code_file, R_OK) == -1)
                	argp_usage(state);
		errno = 0;
		if (errno != 0)
			argp_usage(state);
		break;
	default:
      		return ARGP_ERR_UNKNOWN;
	}
	return 0;

}


void seek_and_write (FILE *f, long offset, void* buffer, size_t nb_bytes, struct args args) {
        if (fseek(f, offset, SEEK_SET))
                errx(EX_SOFTWARE, "fseek () failed : %s.", args.elf_file);
        if (fwrite(buffer, nb_bytes, 1, f) == 0)
                errx(EX_SOFTWARE, "fwrite () failed : %s.", args.elf_file);
}


static struct argp argp = {options, option_parser, args_doc, doc, 0, 0, 0};

int main (int argc, char *argv[]) {
	struct args args;

	args.elf_file = NULL;
	args.bin_code_file = NULL;
	args.section_name = "default";
	args.base_addr = NULL;
	args.modify_entry = false;

	argp_parse(&argp, argc, argv, 0, 0, &args);

	int fd;
	Elf *e;
	Elf64_Ehdr *exhd;
	Elf64_Phdr *phdr;
	size_t n;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EX_SOFTWARE, "ELF library initialization failed : %s", elf_errmsg(ELF_INIT_FAILED));

	if ((fd = open(args.elf_file, O_RDWR, 0)) < 0)
		err(EX_NOINPUT, "open %s failed", args.elf_file);

	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(EX_SOFTWARE, "elf_begin () failed : %s.", elf_errmsg(ELF_BEGIN_FAILED));

	/* Get the header (only if 64-bits) */
	if ((exhd = elf64_getehdr(e)) == NULL)
		errx(EX_SOFTWARE, "elf64_getehdr () failed : %s.", elf_errmsg(ELF_GETEHDR_FAILED));

	/* Get number of program headers */
	if (elf_getphdrnum(e, &n) != 0)
		errx(EX_DATAERR, "elf_getphdrnum () failed : %s.", elf_errmsg(ELF_GETPHDRNUM_FAILED));

	/* Get pointer to array of all program headers */
	if ((phdr = elf64_getphdr(e)) == NULL)
		errx(EX_SOFTWARE, "elf64_getphdr () failed : %s.", elf_errmsg(ELF_GETPHDR_FAILED));

	int index_pt_note = -1;
	for (size_t i = 0; i < n; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			index_pt_note = i;
			break;
		}
	}

	FILE *felf;
        FILE *fbin;
        long offset;

	if ((felf = fdopen(fd, "w")) == NULL)
		err(EX_NOINPUT, "fdopen () failed : %s.", args.elf_file);

	if ((fbin = fopen(args.bin_code_file, "r")) == NULL)
		err(EX_NOINPUT, "fopen () failed : %s.", args.bin_code_file);

	if(fseek(felf, 0, SEEK_END))
		errx(EX_SOFTWARE, "fseek () failed : %s.", args.elf_file);

	offset = ftell(felf);

	size_t size_code = 0;
	char c;
	while ((c = fgetc(fbin)) != EOF) {
		if (fputc(c, felf) == EOF)
			err(EX_IOERR, "fputc () failed : %s.", args.elf_file);
		size_code++;
	}

	long addr = strtol(args.base_addr, NULL, 0);
	int mod = (addr - offset) % 4096;
	if (mod)
		addr += 4096 - mod;

        Elf64_Shdr *shdr;
	Elf_Scn *scn = NULL;
        size_t shstrndx;

	if (elf_getshdrstrndx(e, &shstrndx) != 0)
		errx(EX_SOFTWARE, "elf_getshdrstrndx () failed : %s.", elf_errmsg(ELF_GETSHDRIDX_FAILED));

	char *name;
	scn = elf_nextscn(e, scn);
	do {
		if ((shdr = elf64_getshdr(scn)) == NULL)
			errx(EX_SOFTWARE, "getshdr () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));
		if ((name = elf_strptr (e, shstrndx, shdr->sh_name)) == NULL)
			errx(EX_SOFTWARE, "elf_strptr () failed : %s.", elf_errmsg(ELF_STRPTR_FAILED));
		if (!strcmp(name, ".note.ABI-tag"))
			break;
	} while ((scn = elf_nextscn(e, scn)) != NULL);

	size_t idx_sec = elf_ndxscn(scn);
	shdr->sh_type = SHT_PROGBITS;
	shdr->sh_addr = addr;
	shdr->sh_offset = offset;
	shdr->sh_size = size_code;
	shdr->sh_addralign = 16;
	shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;

	seek_and_write(felf, exhd->e_shoff + exhd->e_shentsize * idx_sec, shdr, exhd->e_shentsize, args);

	Elf_Scn *temp_scn = NULL;
	Elf64_Shdr *temp_shdr;
	Elf64_Shdr save_shdr = *shdr;

	size_t temp_idx = idx_sec;
	int move = 0;

	temp_scn = elf_getscn(e, temp_idx - 1);
        if ((temp_shdr = elf64_getshdr(temp_scn)) == NULL)
                errx(EX_SOFTWARE, "getshdr () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));
	if (temp_shdr->sh_addr > shdr->sh_addr)
		move = -1;

	if (move == 0) {
		temp_scn = elf_getscn(e, temp_idx + 1);
	       	if ((temp_shdr = elf64_getshdr(temp_scn)) == NULL)
			errx(EX_SOFTWARE, "getshdr () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));
		if (temp_shdr->sh_addr < shdr->sh_addr)
			move = 1;
	}

	/* We keep the if move != 0 because move could be modified in the previous if */
	if (move != 0) {
		while (((temp_shdr->sh_addr < save_shdr.sh_addr) && move > 0) || ((temp_shdr->sh_addr > save_shdr.sh_addr) && move < 0)) {
			*shdr = *temp_shdr;
	               	if (shdr->sh_link != 0)
                                shdr->sh_link -= move;
			seek_and_write(felf, exhd->e_shoff + exhd->e_shentsize * temp_idx, shdr, exhd->e_shentsize, args);
			temp_idx += move;
			shdr = temp_shdr;
			temp_scn = elf_getscn(e, temp_idx + move);
                        if ((temp_shdr = elf64_getshdr(temp_scn)) == NULL)
                                errx(EX_SOFTWARE, "getshdr () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));
			if (temp_shdr->sh_addr == 0)
				break;
		}
		seek_and_write(felf, exhd->e_shoff + exhd->e_shentsize * temp_idx, &save_shdr, exhd->e_shentsize, args);
	}

	Elf_Scn *scn_shstrtab = elf_getscn(e, exhd->e_shstrndx);
	if ((shdr = elf64_getshdr(scn_shstrtab)) == NULL)
		errx(EX_SOFTWARE, "getshdrzozz () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));

	seek_and_write(felf, save_shdr.sh_name + shdr->sh_offset, args.section_name, strlen(args.section_name) + 1, args);

	phdr[index_pt_note].p_type = PT_LOAD;
	phdr[index_pt_note].p_offset = offset;
	phdr[index_pt_note].p_vaddr = addr;
	phdr[index_pt_note].p_paddr = addr;
	phdr[index_pt_note].p_filesz = size_code;
	phdr[index_pt_note].p_memsz = size_code;
	phdr[index_pt_note].p_flags = PF_R | PF_X;
	phdr[index_pt_note].p_align = 0x1000;

	seek_and_write(felf, exhd->e_phoff + exhd->e_phentsize * index_pt_note, &phdr[index_pt_note], exhd->e_phentsize, args);

	if (args.modify_entry) {
		exhd->e_entry = addr;
		seek_and_write(felf, 0, exhd, exhd->e_ehsize, args);
	}
	else {
		scn = NULL;
        	while ((scn = elf_nextscn(e, scn)) != NULL) {
                	if ((shdr = elf64_getshdr(scn)) == NULL)
                        	errx(EX_SOFTWARE, "getshdr () failed : %s.", elf_errmsg(ELF_GETSHDR_FAILED));
	                if ((name = elf_strptr(e, shstrndx, shdr->sh_name)) == NULL)
        	                errx(EX_SOFTWARE, "elf_strptr () failed : %s.", elf_errmsg(ELF_STRPTR_FAILED));
	        	if (!strcmp(name, ".got.plt"))
                        	break;
        	}
		seek_and_write(felf, shdr->sh_offset + OFFSET_GOT_FCT, &addr, sizeof(addr), args);
	}

	elf_end(e);
	fclose(felf);
	fclose(fbin);
	close(fd);

	return 0;
}
