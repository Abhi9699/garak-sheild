# Garak-Shield: Automated LLM Security Scanner with Professional Reporting

This project automates scanning of Large Language Models (LLMs) for critical vulnerabilities using [Garak](https://github.com/NVIDIA/garak) and deploys an interactive, professional HTML report hosted on GitHub Pages.

## Features
- Coverage of OWASP Top 10 LLM vulnerability categories
- Automated scanning on GitHub push & pull request triggers
- Clear, interactive report with charts and detailed findings
- Zero cost: Uses Hugging Face free-tier models with tokens from secrets
- Easily extendable and customizable scanning probes

## Setup

1. Add your Hugging Face Token to the repository secrets as `HF_TOKEN`
2. Push code to the `main` branch to trigger scans
3. Reports auto-generated and available at:
   `https://<your_github_username>.github.io/garak-shield/`

## How it Works

- GitHub Action runs Garak CLI scanning against Hugging Face Inference API for `Qwen/Qwen3-0.6B`
- Passes probes covering key LLM security weaknesses including OWASP Top 10 categories
- Generates interactive vulnerability report using Plotly and Jinja2
- Publishes report via GitHub Pages (served from `/docs` folder)

## Contributing

Contributions are welcome! Please open issues or PRs to improve scans, probes, or reporting.

## License

MIT License - See LICENSE file
