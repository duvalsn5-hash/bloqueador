# Bloqueador de Anúncios

App Android que bloqueia anúncios, rastreadores, malware e phishing por DNS, usando uma VPN local
(nenhum tráfego sai do celular para servidores do app).

Desenvolvido por **Edivaldo Nascimento · Iahope-Technology**.

## Como gerar o APK

1. Cada envio para a branch `main` compila o app automaticamente no GitHub Actions.
2. Aba **Actions** > compilação mais recente > **Artifacts** > `Bloqueador-apk`.
3. O APK oficial (`Bloqueador-Iahope-Technology.apk`) é assinado com a chave guardada nos Secrets,
   então as atualizações instalam por cima da versão anterior.

## Estrutura

- `app/src/main/java/com/exemplo/bloqueador/` – código Kotlin
  - `AdVpnService.kt` – VPN local que filtra o DNS
  - `Blocklist.kt` – download e consulta das listas de bloqueio
  - `MainActivity.kt` – tela principal
- `.github/workflows/build.yml` – compilação automática

Veja também [SECURITY.md](SECURITY.md).
