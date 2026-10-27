"""Reproducible simulated-latency benchmark; never calls cloud APIs."""
import json
import statistics
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import aws_stack_snapshot as stack


def main():
    services = ['rds', 's3', 'ecr', 'lambda']
    def collector(args):
        time.sleep(0.05)
        return {'probe': {'ok': True, 'data': []}}
    samples = {}
    with patch.object(stack, 'aws_json', return_value={'ok': True, 'data': {'Account': '123456789012'}}), patch.dict(stack.COLLECTORS, {key: collector for key in services}):
        for workers in (1, 4):
            durations = []
            for _ in range(3):
                args = stack.parse_args(['--region', 'eu-west-1', '--services', ','.join(services), '--max-workers', str(workers)])
                start = time.perf_counter()
                result = stack.build_report(args)
                assert result['status'] == 'complete'
                durations.append((time.perf_counter() - start) * 1000)
            samples[workers] = statistics.median(durations)
    print(json.dumps({'method': '4 mocked independent collectors, 50ms each, median of 3 runs', 'serial_ms': round(samples[1], 2), 'four_workers_ms': round(samples[4], 2), 'simulated_speedup': round(samples[1] / samples[4], 2), 'live_cloud_calls': 0, 'limitation': 'Illustrates concurrent scheduling only; not a production performance guarantee.'}, indent=2))


if __name__ == '__main__':
    main()
