# pcapAdFilter

Script em Python para estimar o volume de tráfego relacionado a publicidade em capturas de rede (`.pcap`), usando resoluções DNS para mapear domínios de anúncios para IPs.

## Base academia

Este código foi utilizado como base prática no artigo:

**Analyzing the Influence of Online Advertisements on ISP Network Traffic**

> **Autores:** **Renan Augusto Redel, Douglas Zietz, Vitor Uchikawa, Ricardo J. Pfitscher**  
> **Evento:** WGRS 2024 (SBC)  
> **DOI:** [10.5753/wgrs.2024.3235](https://doi.org/10.5753/wgrs.2024.3235)  
> **Página do artigo:** [SBC SOL](https://sol.sbc.org.br/index.php/wgrs/article/view/30087)

Em síntese, o trabalho mede o impacto de anúncios no volume de tráfego. Segundo o resumo do artigo, os resultados apontam pelo menos **11%** de volume relacionado a publicidade no cenário de ISP regional e **38%** em dataset público.

## Como o script funciona

O fluxo implementado em `main.py` segue estes passos:

1. Lê a captura `01.pcap` e extrai respostas DNS (UDP com porta de origem 53).
2. Constrói relações entre hostnames e IPs (registros `A`, `AAAA` e `CNAME`).
3. Carrega domínios suspeitos de publicidade de `flagged_domains.txt`.
4. Marca IPs associados a esses domínios.
5. Percorre novamente o `01.pcap` e soma:
   - Tráfego total (`ip.len`)
   - Tráfego com IP de origem associado a anúncios
6. Imprime total, total relacionado a anúncios e percentual.

## Estrutura do repositório

- `main.py`: lógica principal de análise.
- `flagged_domains.txt`: lista de domínios marcados (um por linha).
- `old_flagged_domains.txt`: versão anterior da lista.

## Requisitos

- Python 3.9+
- Biblioteca `dpkt`

Instalação:

```bash
pip install dpkt
```

## Como executar

1. Coloque o arquivo de captura com nome `01.pcap` na raiz do projeto.
2. Garanta que `flagged_domains.txt` esteja presente.
3. Execute:

```bash
python main.py
```

## Observações metodológicas

- A detecção depende de DNS tradicional visível no PCAP (UDP/53).
- Consultas via DoH/DoT/DoQ não são classificadas por este método.
- O matching de domínios e literal (string exata da lista).
- O cálculo atual considera IP de origem associado a domínio marcado no somatório de bytes.
- A estimativa e sensível a qualidade e cobertura da lista de domínios.

## Fonte da lista de domínios

O código referência listas derivadas de:

- https://github.com/StevenBlack/hosts


