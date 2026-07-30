{ pkgs, xen-orchestra-ce }:

pkgs.testers.runNixOSTest {
  name = "xo-server-service";

  nodes.machine = {
    services.redis.servers.xo = {
      enable = true;
      port = 6379;
    };

    users.groups.xo = { };
    users.users.xo = {
      isSystemUser = true;
      group = "xo";
      home = "/var/lib/xo";
    };

    environment.etc."xo-server/config.toml".text = ''
      datadir = '/var/lib/xo/data'

      [http.listen.0]
      hostname = '127.0.0.1'
      port = 8080

      [redis]
      uri = 'redis://127.0.0.1:6379/0'
    '';

    systemd.services.xo-server = {
      description = "Xen Orchestra Server";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network.target"
        "redis-xo.service"
      ];
      requires = [ "redis-xo.service" ];

      environment.HOME = "/var/lib/xo";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${xen-orchestra-ce}/bin/xo-server";
        User = "xo";
        Group = "xo";
        StateDirectory = "xo";
        RuntimeDirectory = "xo-server";
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("redis-xo.service")
    machine.wait_for_unit("xo-server.service")
    machine.wait_for_open_port(8080)
    machine.succeed("systemctl status xo-server.service --no-pager")
    machine.succeed("systemctl is-active --quiet xo-server.service")
  '';
}
