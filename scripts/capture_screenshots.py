"""
Automated Screenshot Capture Script for SOC Detection Engineering Lab.
Uses Playwright to capture high-resolution authentic screenshots of the live web interface.
"""

import asyncio
import os
from playwright.async_api import async_playwright

async def capture_all():
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    out_dir = os.path.abspath("assets/screenshots")
    os.makedirs(out_dir, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=edge_path if os.path.exists(edge_path) else None,
            headless=True
        )
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # 1. Overview Dashboard
        print("Capturing 01_overview_dashboard.png...")
        await page.goto("http://127.0.0.1:8000/#overview")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "01_overview_dashboard.png"))

        # 2. Alert Workbench
        print("Capturing 02_alert_workbench.png...")
        await page.goto("http://127.0.0.1:8000/#alerts")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "02_alert_workbench.png"))

        # 3. MITRE Matrix
        print("Capturing 04_mitre_attack_matrix.png...")
        await page.goto("http://127.0.0.1:8000/#mitre")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "04_mitre_attack_matrix.png"))

        # 4. Benchmark Lab
        print("Capturing 05_benchmark_metrics.png...")
        await page.goto("http://127.0.0.1:8000/#benchmark")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "05_benchmark_metrics.png"))

        # 5. Telemetry Sandbox
        print("Capturing 06_telemetry_sandbox.png...")
        await page.goto("http://127.0.0.1:8000/#stream")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "06_telemetry_sandbox.png"))

        # 6. Awesome Resources Hub
        print("Capturing 07_awesome_resources_hub.png...")
        await page.goto("http://127.0.0.1:8000/#hub")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "07_awesome_resources_hub.png"))

        # 7. Rules Studio List
        print("Capturing 03a_rules_studio_catalog.png...")
        await page.goto("http://127.0.0.1:8000/#rules")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=os.path.join(out_dir, "03a_rules_studio_catalog.png"))

        # 8. Open Translation Modal (Sigma)
        print("Capturing 03_rules_studio_translator.png...")
        translate_buttons = page.locator("button:has-text('Studio & Translate')")
        if await translate_buttons.count() > 0:
            await translate_buttons.first.click()
            await page.wait_for_timeout(1000)
        await page.screenshot(path=os.path.join(out_dir, "03_rules_studio_translator.png"))

        # 9. KQL Query Translation Tab
        print("Capturing 03b_kql_query_translation.png...")
        kql_button = page.locator("button:has-text('Microsoft Sentinel KQL')")
        if await kql_button.count() > 0:
            await kql_button.click()
            await page.wait_for_timeout(800)
        await page.screenshot(path=os.path.join(out_dir, "03b_kql_query_translation.png"))

        await browser.close()
        print("All clean screenshots successfully captured!")

if __name__ == "__main__":
    asyncio.run(capture_all())
