#!/usr/bin/env python3
"""
PQC-Hybrid TLS Benchmark Automation Script
Measures all KEM × Signature combinations with 20 iterations each
"""

import subprocess
import json
import time
import statistics
from pathlib import Path
from datetime import datetime

# Configuration
TEST_BIN = Path("build/test_pqc_handshake")  # Relative path
CERTS_DIR = Path.home() / "mqtt-vmg-certs"
OUTPUT_DIR = Path("benchmark_results")  # Relative path
HOST = "xxx.xxx.xxx.xxx"  # Replace with your server IP
ITERATIONS = 30  # 30회로 증가
HANDSHAKE_TIMEOUT_MS = 2000  # 2000ms 이상은 타임아웃
ITERATION_DELAY = 0.3  # 300ms 대기 (이전 1초에서 단축)

# Port mapping: Each signature algorithm runs on a different port
SIGNATURE_PORTS = {
    "ECDSA-P256": 8883,  # ECDSA broker
    "MLDSA44": 8884,     # ML-DSA-44 broker
    "MLDSA65": 8885,     # ML-DSA-65 broker
    "MLDSA87": 8886      # ML-DSA-87 broker
}

# CA certificate mapping: Each signature algorithm requires matching CA
SIGNATURE_CA_CERTS = {
    "ECDSA-P256": "ca-ecdsa.pem",
    "MLDSA44": "ca-mldsa44.pem",
    "MLDSA65": "ca-mldsa65.pem",
    "MLDSA87": "ca-mldsa87.pem"
}

# Algorithm configurations
KEM_ALGORITHMS = {
    "X25519": {
        "name": "X25519",
        "nist_level": "Classical",
        "description": "Elliptic Curve Diffie-Hellman"
    },
    # "MLKEM512": {  # 서버 미지원으로 제외
    #     "name": "mlkem512",
    #     "nist_level": "Level 1",
    #     "description": "ML-KEM-512 (Kyber512)"
    # },
    "MLKEM768": {
        "name": "mlkem768",
        "nist_level": "Level 3",
        "description": "ML-KEM-768 (Kyber768)"
    },
    "MLKEM1024": {
        "name": "mlkem1024",
        "nist_level": "Level 5",
        "description": "ML-KEM-1024 (Kyber1024)"
    },
    "X25519MLKEM768": {
        "name": "x25519:mlkem768",
        "nist_level": "Hybrid (Classical + Level 3)",
        "description": "X25519 + ML-KEM-768"
    },
    "X448MLKEM1024": {
        "name": "x448:mlkem1024",
        "nist_level": "Hybrid (Classical + Level 5)",
        "description": "X448 + ML-KEM-1024"
    },
    "SecP256r1MLKEM768": {
        "name": "SecP256r1MLKEM768",
        "nist_level": "Hybrid (P-256 + Level 3)",
        "description": "NIST P-256 + ML-KEM-768"
    },
    "SecP384r1MLKEM1024": {
        "name": "SecP384r1MLKEM1024",
        "nist_level": "Hybrid (P-384 + Level 5)",
        "description": "NIST P-384 + ML-KEM-1024"
    }
}

SIGNATURE_ALGORITHMS = {
    "ECDSA-P256": {
        "name": "ecdsa_secp256r1_sha256",
        "nist_level": "Classical",
        "description": "ECDSA with NIST P-256"
    },
    "MLDSA44": {
        "name": "mldsa44",
        "nist_level": "Level 2",
        "description": "ML-DSA-44 (Dilithium2)"
    },
    "MLDSA65": {
        "name": "mldsa65",
        "nist_level": "Level 3",
        "description": "ML-DSA-65 (Dilithium3)"
    },
    "MLDSA87": {
        "name": "mldsa87",
        "nist_level": "Level 5",
        "description": "ML-DSA-87 (Dilithium5)"
    }
}


def run_single_test(kem_name, sig_name, sig_key, iteration):
    """Run a single handshake test"""
    # Get the correct port and CA cert for this signature algorithm
    port = SIGNATURE_PORTS.get(sig_key, 8883)
    ca_cert = SIGNATURE_CA_CERTS.get(sig_key, "ca-ecdsa.pem")
    
    cmd = [
        str(TEST_BIN),
        "--host", HOST,
        "--port", str(port),  # Use signature-specific port
        "--cert", str(CERTS_DIR / "client-vmg-cert.pem"),
        "--key", str(CERTS_DIR / "client-vmg-key.pem"),
        "--ca", str(CERTS_DIR / ca_cert),  # Use signature-specific CA
        "--kem", kem_name,
        "--sig", sig_name
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            # Parse output to extract metrics
            output = result.stdout
            metrics = {}
            
            for line in output.split('\n'):
                if "Handshake Time:" in line:
                    metrics['handshake_time_ms'] = float(line.split(':')[1].strip().split()[0])
                elif "Bytes Sent:" in line:
                    metrics['bytes_sent'] = int(line.split(':')[1].strip().split()[0])
                elif "Bytes Received:" in line:
                    metrics['bytes_received'] = int(line.split(':')[1].strip().split()[0])
                elif "Certificate Chain Size:" in line:
                    metrics['cert_size'] = int(line.split(':')[1].strip().split()[0])
                elif "Cipher Suite:" in line:
                    metrics['cipher'] = line.split(':')[1].strip()
            
            # Check if handshake time exceeds timeout threshold
            if metrics.get('handshake_time_ms', 0) > HANDSHAKE_TIMEOUT_MS:
                print(f"  ⏱️  Timeout ({metrics['handshake_time_ms']:.0f}ms > {HANDSHAKE_TIMEOUT_MS}ms)")
                return None
            
            # Calculate total traffic
            metrics['total_bytes'] = metrics.get('bytes_sent', 0) + metrics.get('bytes_received', 0)
            
            # CPU cycles (estimated - would need perf tools for accurate measurement)
            # For now, we'll leave this as 0 and it can be measured separately
            metrics['cpu_cycles'] = 0
            
            return metrics
        else:
            print(f"  ❌ Test failed: {result.stderr[:100]}")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"  ⏱️  Timeout")
        return None
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None


def compute_trimmed_statistics(values, trim_count=5):
    """
    아웃라이어를 제거한 통계 계산
    trim_count: 제거할 아웃라이어 개수 (상위 + 하위 합계)
    """
    if len(values) <= trim_count:
        # 데이터가 너무 적으면 trim 안 함
        return compute_statistics(values)
    
    sorted_values = sorted(values)
    # 양쪽에서 균등하게 제거 (5개 → 하위 2개, 상위 3개)
    trim_lower = trim_count // 2
    trim_upper = trim_count - trim_lower
    
    trimmed = sorted_values[trim_lower:-trim_upper] if trim_upper > 0 else sorted_values[trim_lower:]
    
    return {
        'mean': statistics.mean(trimmed),
        'median': statistics.median(trimmed),
        'min': min(trimmed),
        'max': max(trimmed),
        'stddev': statistics.stdev(trimmed) if len(trimmed) > 1 else 0,
        'trimmed_count': len(trimmed),
        'removed_count': len(values) - len(trimmed)
    }


def run_benchmark(kem_key, sig_key):
    """Run benchmark for a specific KEM and Signature combination"""
    kem_config = KEM_ALGORITHMS[kem_key]
    sig_config = SIGNATURE_ALGORITHMS[sig_key]
    
    kem_name = kem_config['name']
    sig_name = sig_config['name']
    port = SIGNATURE_PORTS.get(sig_key, 8883)
    ca_cert = SIGNATURE_CA_CERTS.get(sig_key, "ca-ecdsa.pem")
    
    print(f"\n{'='*70}")
    print(f"Testing: {kem_key} × {sig_key}")
    print(f"  KEM: {kem_config['description']} ({kem_config['nist_level']})")
    print(f"  SIG: {sig_config['description']} ({sig_config['nist_level']})")
    print(f"  Port: {port}")
    print(f"  CA: {ca_cert}")
    print(f"{'='*70}")
    
    results = []
    
    for i in range(1, ITERATIONS + 1):
        print(f"  Iteration {i}/{ITERATIONS}...", end=" ", flush=True)
        
        metrics = run_single_test(kem_name, sig_name, sig_key, i)
        
        if metrics:
            results.append(metrics)
            print(f"✅ {metrics.get('handshake_time_ms', 0):.2f} ms")
            time.sleep(ITERATION_DELAY)  # 성공: 0.3초
        else:
            print("❌ Failed")
            time.sleep(1.0)  # 실패: 1초
    
    if not results:
        print(f"  ❌ All tests failed for {kem_key} × {sig_key}")
        return None
    
    # Calculate statistics (with outlier removal)
    handshake_times = [r['handshake_time_ms'] for r in results]
    total_bytes_list = [r['total_bytes'] for r in results]
    cert_sizes = [r.get('cert_size', 0) for r in results]
    
    # Calculate success rate
    success_rate = (len(results) / ITERATIONS) * 100
    
    # Trimmed statistics (아웃라이어 상위 4개 + 하위 4개 = 8개 제거)
    handshake_stats = compute_trimmed_statistics(handshake_times, trim_count=8)
    traffic_stats = compute_trimmed_statistics(total_bytes_list, trim_count=8)
    
    stats = {
        'kem': kem_key,
        'kem_config': kem_config,
        'sig': sig_key,
        'sig_config': sig_config,
        'iterations': ITERATIONS,
        'successful_iterations': len(results),
        'success_rate': success_rate,  # 성공 확률 (%)
        'handshake_time': handshake_stats,
        'total_traffic': {
            'mean': traffic_stats['mean']
        },
        'cert_size': {
            'mean': statistics.mean(cert_sizes),
        },
        'cpu_cycles': {
            'mean': 0  # Placeholder - macOS에서 정확한 측정 어려움
        },
        'cipher': results[0].get('cipher', 'N/A')
    }
    
    print(f"\n  📊 Results ({len(results)}/{ITERATIONS} successful, {success_rate:.1f}% success rate):")
    print(f"    Handshake Time: {stats['handshake_time']['mean']:.2f} ms (±{stats['handshake_time']['stddev']:.2f}) [trimmed: {handshake_stats['removed_count']} outliers removed]")
    print(f"    Total Traffic:  {stats['total_traffic']['mean']:.0f} bytes")
    print(f"    Cert Size:      {stats['cert_size']['mean']:.0f} bytes")
    
    return stats


def generate_markdown_report(all_results, output_file):
    """Generate markdown report with tables"""
    
    md = []
    md.append("# PQC-Hybrid TLS Benchmark Results")
    md.append("")
    md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md.append(f"**Server:** {HOST}")
    md.append(f"**Ports:** ECDSA=8883, MLDSA44=8884, MLDSA65=8885, MLDSA87=8886")
    md.append(f"**Iterations per combination:** {ITERATIONS}")
    md.append("")
    
    # Summary table
    md.append("## Summary Table")
    md.append("")
    md.append("| # | KEM Algorithm | Signature | NIST Level | Success Rate (%) | Handshake (ms) | Traffic (bytes) | Cert Size (bytes) |")
    md.append("|---|---------------|-----------|------------|------------------|----------------|-----------------|-------------------|")
    
    for idx, result in enumerate(all_results, 1):
        if result:
            kem_level = result['kem_config']['nist_level']
            sig_level = result['sig_config']['nist_level']
            combined_level = f"{kem_level} / {sig_level}"
            
            md.append(f"| {idx} | {result['kem']} | {result['sig']} | {combined_level} | "
                     f"{result['success_rate']:.1f}% | "
                     f"{result['handshake_time']['mean']:.2f} ± {result['handshake_time']['stddev']:.2f} | "
                     f"{result['total_traffic']['mean']:.0f} | "
                     f"{result['cert_size']['mean']:.0f} |")
    
    md.append("")
    
    # Detailed results
    md.append("## Detailed Results")
    md.append("")
    
    for idx, result in enumerate(all_results, 1):
        if result:
            md.append(f"### {idx}. {result['kem']} × {result['sig']}")
            md.append("")
            
            md.append("**Configuration:**")
            md.append(f"- KEM: {result['kem_config']['description']} (NIST {result['kem_config']['nist_level']})")
            md.append(f"- Signature: {result['sig_config']['description']} (NIST {result['sig_config']['nist_level']})")
            md.append(f"- Cipher Suite: {result['cipher']}")
            md.append(f"- Iterations: {result['iterations']}")
            md.append(f"- Successful Tests: {result['successful_iterations']}")
            md.append(f"- **Success Rate: {result['success_rate']:.1f}%**")
            md.append("")
            
            md.append("**Metrics:**")
            md.append("")
            md.append("| Metric | Mean | Median | Min | Max | Std Dev |")
            md.append("|--------|------|--------|-----|-----|---------|")
            md.append(f"| Handshake Time (ms) | {result['handshake_time']['mean']:.2f} | "
                     f"{result['handshake_time']['median']:.2f} | "
                     f"{result['handshake_time']['min']:.2f} | "
                     f"{result['handshake_time']['max']:.2f} | "
                     f"{result['handshake_time']['stddev']:.2f} |")
            md.append(f"| Total Traffic (bytes) | {result['total_traffic']['mean']:.0f} | - | - | - | - |")
            md.append(f"| Certificate Size (bytes) | {result['cert_size']['mean']:.0f} | - | - | - | - |")
            md.append("")
    
    # Performance comparison
    md.append("## Performance Comparison")
    md.append("")
    
    # Sort by handshake time
    sorted_results = sorted([r for r in all_results if r], 
                           key=lambda x: x['handshake_time']['mean'])
    
    md.append("### Fastest Handshake Times")
    md.append("")
    md.append("| Rank | Combination | Time (ms) |")
    md.append("|------|-------------|-----------|")
    for rank, result in enumerate(sorted_results[:10], 1):
        md.append(f"| {rank} | {result['kem']} × {result['sig']} | {result['handshake_time']['mean']:.2f} |")
    md.append("")
    
    # Sort by traffic
    sorted_by_traffic = sorted([r for r in all_results if r], 
                               key=lambda x: x['total_traffic']['mean'])
    
    md.append("### Lowest Traffic")
    md.append("")
    md.append("| Rank | Combination | Traffic (bytes) |")
    md.append("|------|-------------|-----------------|")
    for rank, result in enumerate(sorted_by_traffic[:10], 1):
        md.append(f"| {rank} | {result['kem']} × {result['sig']} | {result['total_traffic']['mean']:.0f} |")
    md.append("")
    
    # Write to file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text('\n'.join(md))
    print(f"\n📄 Report saved to: {output_file}")


def main():
    print("="*70)
    print("  PQC-Hybrid TLS Benchmark Automation")
    print("="*70)
    print(f"Server: {HOST}")
    print(f"Ports: ECDSA=8883, MLDSA44=8884, MLDSA65=8885, MLDSA87=8886")
    print(f"Iterations: {ITERATIONS} per combination")
    print(f"Total tests: {len(KEM_ALGORITHMS)} × {len(SIGNATURE_ALGORITHMS)} × {ITERATIONS} = {len(KEM_ALGORITHMS) * len(SIGNATURE_ALGORITHMS) * ITERATIONS}")
    print("="*70)
    
    # Check test binary
    if not TEST_BIN.exists():
        print(f"❌ Test binary not found: {TEST_BIN}")
        return 1
    
    # Check certificates
    if not (CERTS_DIR / "client-vmg-cert.pem").exists():
        print(f"❌ Certificates not found in: {CERTS_DIR}")
        return 1
    
    all_results = []
    start_time = time.time()
    
    # Run all combinations
    for kem_key in KEM_ALGORITHMS:
        for sig_key in SIGNATURE_ALGORITHMS:
            result = run_benchmark(kem_key, sig_key)
            all_results.append(result)
    
    elapsed = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"✅ Benchmark completed in {elapsed:.1f} seconds")
    print(f"{'='*70}")
    
    # Generate report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_DIR / f"benchmark_report_{timestamp}.md"
    generate_markdown_report(all_results, output_file)
    
    # Save raw JSON data
    json_file = OUTPUT_DIR / f"benchmark_data_{timestamp}.json"
    json_file.write_text(json.dumps(all_results, indent=2))
    print(f"📊 Raw data saved to: {json_file}")
    
    print("\n✅ All done!")
    return 0


if __name__ == "__main__":
    exit(main())

