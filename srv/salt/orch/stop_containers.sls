{% if 'docker' | which %}
stop_docker_service:
  service.dead:
    - name: docker
    - enable: False
    - no_block: True
{% endif %}

{% if 'podman' | which %}
stop_podman_service:
  service.dead:
    - name: podman
    - enable: False
    - no_block: True

stop_podman_containers:
  cmd.run:
    - name: podman stop -a -t 10
    - bg: True
{% endif %}
