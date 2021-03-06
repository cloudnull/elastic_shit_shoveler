#!/usr/bin/env python
# =============================================================================
# Copyright [2013] [kevin carter]
# License Information :
# This software has no warranty, it is provided 'as is'. It is your
# responsibility to validate the behavior of the routines and its accuracy
# using the code provided. Consult the GNU General Public license for further
# details (see GNU General Public License).
# http://www.gnu.org/licenses/gpl.html
# =============================================================================
import argparse
import requests
import multiprocessing
import Queue
import httplib
import json
import logging
import logging.handlers
import os
import sys
import signal
import time
import urlparse
import urllib


LOG = logging.getLogger('elastic-shit-shoveler')


REGIONS = {
    'ord': 'https://storage101.ord1.clouddrive.com',
    'dfw': 'https://storage101.dfw1.clouddrive.com',
    'iad': 'https://storage101.iad1.clouddrive.com',
    'lon': 'https://storage101.lon1.clouddrive.com',
    'syd': 'https://storage101.syd1.clouddrive.com',
    'hkg': 'https://storage101.hkg1.clouddrive.com'
}


def reporter(msg, lvl='info'):
    """Report Any Messages that need reporting.

    :param msg:
    :param lvl:
    """

    try:
        log = getattr(LOG, lvl.lower())
        log(msg)
    except Exception:
        pass


def head_request(url, headers, rpath):
    try:
        _url = urlparse.urljoin(urlparse.urlunparse(url), rpath)
        resp = requests.head(_url, headers=headers)
        reporter(
            msg='INFO: %s %s %s' % (resp.status_code,
                                    resp.reason,
                                    resp.request)
        )
    except Exception as exp:
        reporter(
            'Not able to perform Request ERROR: %s' % exp,
            lvl='error',
        )
    else:
        return resp


def get_request(url, headers, rpath, stream=False):
    try:
        _url = urlparse.urljoin(urlparse.urlunparse(url), rpath)
        resp = requests.get(_url, headers=headers, stream=stream)
        reporter(
            msg='INFO: %s %s %s' % (resp.status_code,
                                    resp.reason,
                                    resp.request),
            lvl='debug'
        )
    except Exception as exp:
        reporter('Not able to perform Request ERROR: %s' % exp, lvl='error')
    else:
        return resp


def downloader(url, rpath, fheaders, local_f, mode):
    """Download an Object."""

    # Perform Object GET
    object_ref = 'Downloading [ %s = %s ]' % (rpath, local_f)
    for rty in retryloop(attempts=5, delay=1, obj=object_ref):
        resp = get_request(
            url=url,
            rpath=rpath,
            headers=fheaders,
            stream=True
        )
        if resp is not None and resp.status_code > 300:
            rty()
        else:
            # Open our source file and write it
            if not os.path.exists(local_f):
                with open(local_f, mode) as f_name:
                    for chunk in resp.iter_content(chunk_size=2048):
                        if chunk:
                            f_name.write(chunk)
                            f_name.flush()
                resp.close()


def mkdir_p(path):
    """'Make the directories required."""

    try:
        if not os.path.isdir(path):
            os.makedirs(path)
    except OSError:
        pass


def ustr(obj):
    """If an Object is unicode convert it.

    :param obj:
    :return:
    """

    if obj is not None and isinstance(obj, unicode):
        return str(obj.encode('utf8'))
    else:
        return obj


def quoter(url, ufile=None):
    """Return a Quoted URL.

    :param url:
    :param ufile:
    :return:
    """

    url = ustr(obj=url)

    if ufile is not None:
        ufile = ustr(obj=ufile)

    if ufile is not None:
        return urllib.quote(
            '%s/%s' % (url, ufile)
        )
    else:
        return urllib.quote(
            '%s' % url
        )


def _last_marker(f_path, l_obj):
    """Set Marker.

    :param f_path:
    :param l_obj:
    :return str:
    """

    return '%s&marker=%s' % (f_path, quoter(url=l_obj))


def _obj_index(url, headers, b_path, m_path):
    f_list = []
    l_obj = None

    while True:
        for rty in retryloop(attempts=5, obj=m_path):
            try:
                resp = get_request(
                    url=url, rpath=m_path, headers=headers
                )
                for obj in resp.json():
                    f_list.append(obj['name'])

                last_obj_in_list = f_list[-1].split('=')[0]
                if l_obj is last_obj_in_list:
                    return f_list
                else:
                    l_obj = last_obj_in_list
                    m_path = _last_marker(
                        f_path=b_path, l_obj=last_obj_in_list
                    )
            except Exception:
                rty()


def _arg_parser():
    """Setup argument Parsing."""

    parser = argparse.ArgumentParser(
        usage='%(prog)s',
        description='Rackspace Jungle Disk file Downloader',
        epilog=''
    )

    parser.add_argument(
        '--log-file',
        help='Log file',
        default='shoveler.log'
    )

    parser.add_argument(
        '--debug',
        help='Make the script verbose',
        action='store_true',
        default=False
    )

    parser.add_argument(
        '--verbose',
        help='Make the script verbose',
        action='store_true',
        default=False
    )

    parser.add_argument(
        '-t',
        '--token',
        help='Set the token to be used',
        metavar='',
        default=os.environ.get('OS_TOKEN', None)
    )

    parser.add_argument(
        '-r',
        '--region',
        help='Region Choices: %s' % REGIONS.keys(),
        choices=REGIONS.keys(),
        metavar='',
        default=os.environ.get('OS_REGION', None)
    )

    parser.add_argument(
        '-a',
        '--account-id',
        help='Set the account ID of the cloud files account',
        metavar='',
        default=os.environ.get('OS_ACCOUNT', None)
    )

    subpar = parser.add_subparsers()
    download = subpar.add_parser(
        'download',
        help='Download the objects.'
    )
    download.set_defaults(method='download')
    download.add_argument(
        '-e',
        '--export',
        help='Name of the container. ACTION: container=local/path',
        metavar='',
        action='append',
        default=[]
    )

    test = subpar.add_parser(
        'test',
        help='Index and test a download operation.'
    )

    test.add_argument(
        '-e',
        '--export',
        help='Name of the container. ACTION: container=local/path',
        metavar='',
        action='append',
        default=[]
    )
    test.set_defaults(method='test')

    return parser


def load_logging(cmd, container):
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s:%(levelname)s => %(message)s"
    )

    LOG.setLevel(logging.DEBUG)
    filehandler = logging.FileHandler(
        filename='%s.%s' % (container, cmd['log_file']),
    )

    filehandler.setLevel(logging.DEBUG)
    filehandler.setFormatter(formatter)
    LOG.addHandler(filehandler)

    streamhandler = logging.StreamHandler()
    if cmd['verbose'] is True:
        streamhandler.setLevel(logging.DEBUG)
    else:
        streamhandler.setLevel(logging.ERROR)
    streamhandler.setFormatter(formatter)
    LOG.addHandler(streamhandler)


def set_headers(token):
    return {
        'User-Agent': 'elastic-shit-shoveler',
        'X-Storage-Token': token
    }


def worker_proc(job_action, concurrency, queue, kwargs, daemon=True):
    """Requires the job_action and num_jobs variables for functionality.

    :param job_action: What function will be used
    :param concurrency: The number of jobs that will be processed
    :param queue: The Queue
    :param kwargs: Optional
    :param daemon: Bol

    All threads produced by the worker are limited by the number of concurrency
    specified by the user. The Threads are all made active prior to them
    processing jobs.
    """

    def stop(*args):
        if jobs:
            for job in jobs:
                job.terminate()
        if join_jobs:
            for job in join_jobs:
                job.terminate()

    arguments = []
    for item in [queue, kwargs]:
        if item is not None:
            arguments.append(item)

    jobs = [multiprocessing.Process(target=job_action,
                                    args=tuple(arguments))
            for _ in xrange(concurrency)]
    join_jobs = []

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, stop)
    for _job in jobs:
        join_jobs.append(_job)
        _job.daemon = daemon
        _job.start()

    for job in join_jobs:
        job.join()


class IndicatorThread(object):
    """Creates a visual indicator while normally performing actions."""

    def __init__(self, work_q=None, system=True, debug=False, msg=None):
        """System Operations Available on Load.

        :param work_q:
        :param system:
        """

        self.debug = debug
        self.work_q = work_q
        self.system = system
        self.msg = msg
        self.job = None

    def __enter__(self):
        if self.debug is False:
            self.indicator_thread()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.debug is False:
            self.job.terminate()
            print('Done.')

    def indicator(self):
        """Produce the spinner."""

        while self.system:
            busy_chars = ['|', '/', '-', '\\']
            for bc in busy_chars:
                # Fixes Errors with OS X due to no sem_getvalue support
                if self.work_q is not None:
                    if not sys.platform.startswith('darwin'):
                        size = self.work_q.qsize()
                        if size > 0:
                            note = 'Number of Jobs in Queue = %s ' % size
                        else:
                            note = 'Please Wait... '
                    else:
                        note = 'Please Wait... '
                else:
                    note = 'Please Wait... '
                if self.msg is None:
                    sys.stdout.write('\rProcessing - [ %s ] - %s' % (bc, note))
                else:
                    sys.stdout.write(
                        '\r%s - [ %s ] - %s' % (self.msg, bc, note)
                    )
                sys.stdout.flush()

                time.sleep(.1)
                self.system = self.system

    def indicator_thread(self):
        """indicate that we are performing work in a thread."""

        self.job = multiprocessing.Process(target=self.indicator)
        self.job.start()
        return self.job


def job_processer(num_jobs, objects, job_action, concur, kwargs=None):
    """Process all jobs in batches.

    :param num_jobs:
    :param objects:
    :param job_action:
    :param concur:
    :param kwargs:
    """

    count = 0
    if num_jobs < 30000:
        batch_size = num_jobs
    else:
        batch_size = 30000

    for work in range(0, num_jobs, batch_size):
        count += 1
        print('Job Count %s' % count)
        work_q = basic_queue(objects[work:work + batch_size])

        with IndicatorThread(work_q=work_q):
            worker_proc(
                job_action=job_action,
                concurrency=concur,
                queue=work_q,
                kwargs=kwargs
            )
        work_q.close()


def basic_queue(iters=None):
    """Uses a manager Queue, from multiprocessing.

    All jobs will be added to the queue for processing.
    :param iters:
    """

    worker_q = multiprocessing.Queue()
    if iters is not None:
        for _dt in iters:
            worker_q.put(_dt)
    return worker_q


def get_from_q(queue):
    """Returns the file or a sentinel value.

    :param queue:
    :return item|None:
    """

    try:
        wfile = queue.get(timeout=5)
    except Queue.Empty:
        return None
    else:
        return wfile


def doerator(work_q, kwargs):
    """Do Jobs until done.

    :param work_q:
    :param kwargs:
    """
    job = kwargs.pop('cf_job')
    remote_path = kwargs.pop('path')
    local_dir = kwargs.pop('dir')

    while True:
        # Get the file that we want to work with
        index = get_from_q(queue=work_q)

        # If Work is None return None
        if index is None:
            break
        else:
            index = index[1]
            if 'name' in index:
                # Do the job that was provided
                chunks = index['data_paths'].keys()

                if len(chunks) > 1:
                    kwargs['mode'] = 'ab'
                else:
                    kwargs['mode'] = 'wb'

                for wfile in chunks:
                    kwargs['rpath'] = quoter(
                        remote_path, ufile=index['data_paths'][wfile]
                    )
                    kwargs['local_f'] = os.path.join(local_dir, index['name'])
                    job(**kwargs)
            else:
                print('Reference without a pointer [ %s ]' % index)


def set_unique_dirs(object_list, root_dir):
    """From an object list create a list of unique directories.

    :param object_list:
    :param root_dir:
    """

    unique_dirs = []
    for obj in object_list:
        full_path = os.path.join(root_dir, obj)
        dir_path = full_path.split(
            os.path.basename(full_path)
        )[0].rstrip(os.sep)
        unique_dirs.append(dir_path)
    return set(unique_dirs)


def retryloop(attempts, timeout=None, delay=None, backoff=1, obj=None):
    """Enter the amount of retries you want to perform.

    The timeout allows the application to quit on "X".
    delay allows the loop to wait on fail. Useful for making REST calls.

    :param attempts:
    :param timeout:
    :param delay:
    :param backoff:
    """

    starttime = time.time()
    success = set()
    for _ in range(attempts):
        success.add(True)
        yield success.clear
        if success:
            return
        duration = time.time() - starttime
        if timeout is not None and duration > timeout:
            reporter('Timeout Error', lvl='error')
        if delay:
            time.sleep(delay)
            delay *= backoff
    else:
        msg = 'RetryError: FAILED "%s" after "%s" Attempts' % (obj, attempts)
        reporter(msg, lvl='error')


def recurse_files(compiled_files, pointers, dir_ref='ROOT', dir_name=None):
    """Recursivly index all files found in the container.

    :param dir_ref:
    :param dir_name:
    """

    def queue_loader(_dir_ref, _dir_name):
        for my_file in pointers:
            if my_file.startswith(_dir_ref):
                obj = {'my_file': my_file, '_dir_name': _dir_name}
                queue.put(obj)

    def threader():
        def stop(*args):
            if jobs:
                for job in jobs:
                    job.terminate()
            if join_jobs:
                for job in join_jobs:
                    job.terminate()

        jobs = [
            multiprocessing.Process(target=worker, args=(queue,))
            for _ in range(50)
        ]
        join_jobs = []

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGHUP, stop)
        for job in jobs:
            job.start()
            join_jobs.append(job)

        for job in join_jobs:
            job.join()

    def worker(my_queue):
        while True:
            action_args = get_from_q(my_queue)
            if action_args is not None:
                action_args['q'] = my_queue
                processer(**action_args)
            else:
                break

    def processer(q, my_file, _dir_name):
        msf = my_file.split('/')
        if len(msf) >= 4:
            if msf[1] in compiled_files:
                _cf = compiled_files[msf[1]]
                if _dir_name is None:
                    _cf['name'] = msf[3]
                else:
                    _cf['name'] = os.path.join(_dir_name, msf[3])
                compiled_files[msf[1]] = _cf
            else:
                if msf[2] == 'dir':
                    if _dir_name is None:
                        queue_loader(
                            _dir_ref=msf[1],
                            _dir_name=msf[3],
                        )
                    else:
                        queue_loader(
                            _dir_ref=msf[1],
                            _dir_name=os.path.join(_dir_name, msf[3]),
                        )
                else:
                    queue_loader(
                        _dir_ref=msf[1],
                        _dir_name=_dir_name,
                    )
        else:
            print('Ignored Reference [ %s ]' % my_file)

    manager = multiprocessing.Manager()
    queue = manager.Queue()
    queue_loader(dir_ref, dir_name)
    threader()


def export_operation(cmd, container, directory):
    manager = multiprocessing.Manager()
    compiled_files = manager.dict()
    pointers = manager.list()

    fheaders = set_headers(token=cmd['token'])
    path = 'v1/%s/%s' % (cmd['account_id'], container)
    url = urlparse.urlparse(REGIONS[cmd['region']])
    encoded_path = ustr(path)

    # Check to see if the container exists
    req = head_request(url=url, headers=fheaders, rpath=encoded_path)

    if any([req.status_code == 404, req.status_code == 401]):
        print('container %s not found.' % container)
    else:
        with IndicatorThread(msg='Indexing Cloud Files'):
            base_path = marked_path = (
                '%s?limit=10000&format=json' % encoded_path
            )
            file_list = _obj_index(
                url=url,
                headers=fheaders,
                b_path=base_path,
                m_path=marked_path
            )

        with IndicatorThread(msg='Building Download Index'):
            for my_file in file_list:
                if my_file.startswith('FILES'):
                    split_file = my_file.split('/')

                    if split_file[1] not in compiled_files:
                        cf = compiled_files[split_file[1]] = {}
                    else:
                        cf = compiled_files[split_file[1]]

                    dp = cf['data_paths'] = {}
                    dp[split_file[2]] = my_file
                    compiled_files[split_file[1]] = cf
                else:
                    pointers.append(my_file)

            # Recurse through all of the pointers and locate the files.
            recurse_files(compiled_files, pointers)

        compiled_files = dict(compiled_files)
        del pointers

        if cmd['verbose'] is True:
            print(json.dumps(compiled_files, indent=2))

        compiled_files_items = compiled_files.items()
        file_names = [
            inode[1]['name'] for inode in compiled_files_items
            if 'name' in inode[1]
        ]

        number_of_jobs = len(compiled_files)

        if number_of_jobs >= 50:
            concurency = 50
        else:
            concurency = number_of_jobs

        download_args = {
            'url': url,
            'cf_job': downloader,
            'fheaders': fheaders,
            'path': encoded_path,
            'dir': directory
        }

        if cmd['method'] is 'download':
            with IndicatorThread(msg='Building Local Directory Structure'):
                for dirs in set_unique_dirs(file_names, directory):
                    mkdir_p(dirs)

            job_processer(
                num_jobs=number_of_jobs,
                objects=compiled_files_items,
                job_action=doerator,
                concur=concurency,
                kwargs=download_args
            )

        with IndicatorThread(msg='Building Post Action Report'):
            msg__compiled_files = (
                'Number of compiled Object Found in the Container: %s'
                % number_of_jobs
            )

            msg_with_files = (
                'Number of files with Names: %s' % len(file_names)
            )

            files_no_name = [
                inode for inode in compiled_files.items()
                if 'name' not in inode[1]
            ]

            msg_without_files = (
                'Number of data objects without a file Name: %s'
                % len(files_no_name)
            )

        print('\nPost action Report for %s:' % container)
        print(''.join(['=' for _ in range(len(msg__compiled_files))]))
        for rep in [msg__compiled_files, msg_with_files, msg_without_files]:
            print(rep)

        if len(files_no_name) > 0:
            localreport = os.path.join(os.getcwd(), 'unknown_files.log')
            with open(localreport, 'wb') as report:
                for line in files_no_name:
                    try:
                        report.write('%s\n' % list(line))
                    except Exception as exp:
                        print(exp, line)
            print('A report for all unknown data objects'
                  ' can be found here %s\n' % localreport)


def main():
    parser = _arg_parser()
    if len(sys.argv) < 2:
        raise SystemExit(parser.print_help())

    cmd = vars(parser.parse_args())

    if cmd['debug'] is True:
        cmd['verbose'] = True
        httplib.HTTPConnection.debuglevel = 1

    # Load logging
    for export in cmd['export']:
        container, local_path = export.split('=')
        load_logging(cmd, container)
        # Set all of the storage objects that we need
        export_operation(cmd=cmd, container=container, directory=local_path)


if __name__ == "__main__":
    main()
















