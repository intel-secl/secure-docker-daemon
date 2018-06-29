#!/usr/bin/python

from __future__ import print_function
import sys
import argparse
import collections
import json
import re
import dateutil.parser
import datetime


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def main():
    prog = 'log-analyze.py'
    description = ('''A tool to filter and print docker logrus JSONFormatted log-files.
                      E.g., to get driver interface functions with record numbers, relative and cummulative time, run "log-analyze.py -F \'\(\*Driver\)\.[A-Z].*\' -p text-pretty -n -r -c". Or to get average duration of calls to driver Get, run "log-analyze.py -F '\(\*Driver\)\.Get' -c -C msg '.*Get called.*' -s ".
                   ''')
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument('infile', nargs='?', type=argparse.FileType(),
                        help='a log-file to be analyzed/printed')
    parser.add_argument('-d', '--display-regexp',
                        action='append',
                        help='regexp for fields to be printed (if absent, all are printed; if multiple are present, fields matching any provided value are printed )')
    parser.add_argument('-f', '--filter-regexp',
                        nargs=2,
                        action='append',
                        help='tuple <field-regexp,value-regexp> to filter records where in field matching field-regexp the corresponding value matches value-regexp (option can be repeated with any match result in a print, if option is absent, everything is printed')
    parser.add_argument('-F', '--function-filter-regexp',
                        nargs=1,
                        action='append',
                        help='filter on function names')
    parser.add_argument('-p', '--print-format',
                        choices=['json', 'json-pretty', 'csv', 'text-pretty'],
                        default='text-pretty',
                        help='print format')
    parser.add_argument('-n', '--add-record-num',
                        action='store_true',
                        help='add record (line) number to allow cross-referencing to source file')
    parser.add_argument('-r', '--add-relative-time',
                        action='store_true',
                        help='add relative time')
    parser.add_argument('-c', '--add-cummulative-time',
                        action='store_true',
                        help='add cummulative time')
    parser.add_argument('-C', '--cummulative-time-reset-regexp',
                        nargs=2,
                        action='append',
                        help='tuple <field-regexp,value-regexp> to select condition where cummulative timer is reset. option can be repeated with any match result resulting in reset, if option is absent, timer is reset only at first record. Note pattern is applied _after_ filtering!')
    parser.add_argument('-s', '--print-statistics',
                        action='store_true',
                        help='print some statics, only meaningful in conjunction of -C and appropriate filtering with -f or -F of field to include exactly the beginning of the measurement (i.e., what you use in -C) plus the desired end plus optional intermerdiary events. the relative time measurement at time of reset is between the previous reset and the last filtered event before the current reset event!')
    options = parser.parse_args()

    doFilterRecords = ((options.filter_regexp != None) or (options.function_filter_regexp != None))
    if doFilterRecords:
        filter_re = []
        if (options.filter_regexp != None):
            for rule in options.filter_regexp:
                fe = rule[0]
                ve = rule[1]
                filter_re.append([re.compile(fe), re.compile(ve)])
        if (options.function_filter_regexp != None):
            for rule in options.function_filter_regexp:
                ve = rule[0]
                filter_re.append([re.compile('caller'), re.compile(".*u'Name': u'{0}', u'File':.*".format(ve))])

    doDisplayFilter = (options.display_regexp != None)
    if doDisplayFilter:
        display_re = re.compile("|".join(options.display_regexp))

    doCummulReset = (options.cummulative_time_reset_regexp != None)
    if doCummulReset:
        cummul_reset_re = []
        for rule in options.cummulative_time_reset_regexp:
            fe = rule[0]
            ve = rule[1]
            cummul_reset_re.append([re.compile(fe), re.compile(ve)])

    def dump_obj_json_pretty(o):
        json.dump(o, sys.stdout, indent=4),
        sys.stdout.write('\n')

    def dump_obj_json(o):
        json.dump(o, sys.stdout),
        sys.stdout.write('\n')

    def dump_obj_csv(o):
        sys.stdout.write('{0}\n'.format(",\t".join(o.values())))

    def dump_obj_text_pretty(o):
        if options.add_record_num:
            r = o['record_num']
            r_format = '{0:>5}  '
        else:
            r = ''
            r_format = ''
        if options.add_relative_time:
            rt_format = '{1:>30}  '
            rt = o['relative_time']
        else:
            rt_format = ''
            rt = ''
        if options.add_cummulative_time:
            ct_format = '{2:>18}  '
            ct = o['cummulative_time']
        else:
            ct_format = ''
            ct = ''
        if 'caller' in o and 'Name' in o['caller']:
            n = o['caller']['Name']
            n_format = '{3:<30}  '
        else:
            n = ''
            n_format = ''
        if 'msg' in o:
            m = o['msg'].replace('\n', '\\n')
            m_format = '{4:}'
        else:
            m = ''
            m_format = ''
        sys.stdout.write(''.join([r_format, rt_format, ct_format, n_format, m_format, '\n']).format(r, rt, ct, n, m))
    dump_obj_funcs = {
        'json-pretty': dump_obj_json_pretty,
        'json': dump_obj_json,
        'csv': dump_obj_csv,
        'text-pretty': dump_obj_text_pretty,
    }
    dump_obj = dump_obj_funcs[options.print_format]

    infile = options.infile or sys.stdin
    record_num = 0
    t_prev = -1
    t_start = -1
    cummul_num = 0
    cummul_sum = -1
    cummul_min = datetime.timedelta.max
    cummul_max = datetime.timedelta.min
    cummul_last_t = -1
    for line in infile:
        record_num += 1
        try:
            obj = json.loads(line)

            if options.add_cummulative_time and t_start == -1:
                ts = obj['time']
                t_start = dateutil.parser.parse(ts)

            doPrint = True
            if doFilterRecords:
                doPrint = False
                for patterns in filter_re:
                    fp = patterns[0]
                    vp = patterns[1]
                    for fm in filter(fp.match, obj.keys()):
                        if vp.match(str(obj[fm])):
                            doPrint = True
                            break
                    else:
                        continue
                    break

            if doPrint and doCummulReset:
                ts = obj['time']
                t = dateutil.parser.parse(ts)
                for patterns in cummul_reset_re:
                    fp = patterns[0]
                    vp = patterns[1]
                    for fm in filter(fp.match, obj.keys()):
                        if vp.match(str(obj[fm])):
                            cummul_num += 1
                            if cummul_sum == -1:
                                cummul_sum = 0
                            else:
                                # Note: we do not measure to the reset-time but the previous filtered event!
                                diff = cummul_last_t - t_start
                                if diff > cummul_max:
                                    cummul_max = diff
                                if diff < cummul_min:
                                    cummul_min = diff
                                if cummul_sum == 0:
                                    cummul_sum = diff
                                else:
                                    cummul_sum += diff
                            t_start = t
                            break
                    else:
                        continue
                    break
                cummul_last_t = t

            if doPrint:
                if doDisplayFilter:
                    disp_obj = {}
                    for dm in filter(display_re.match, obj.keys()):
                        disp_obj[dm] = obj[dm]
                else:
                    disp_obj = obj
                if options.add_record_num:
                    disp_obj['record_num'] = record_num

                if options.add_relative_time or options.add_cummulative_time:
                    ts = obj['time']
                    t = dateutil.parser.parse(ts)
                    if options.add_relative_time:
                        if t_prev == -1:
                            t_prev = t
                            t_rel = ts
                        else:
                            t_rel = t - t_prev
                            t_prev = t
                        disp_obj['relative_time'] = t_rel
                    if options.add_cummulative_time:
                        disp_obj['cummulative_time'] = t - t_start
                dump_obj(disp_obj)
        except ValueError as e:
            eprint('WARN: ignoring line "{0}": {1}'.format(line.rstrip(), e))
    if options.print_statistics:
        if cummul_num > 0:
            # "close" last measurement
            diff = cummul_last_t - t_start
            if diff > cummul_max:
                cummul_max = diff
            if diff < cummul_min:
                cummul_min = diff
            if cummul_sum == 0:
                cummul_sum = diff
            else:
                cummul_sum += diff
            sys.stdout.write(''''
Statics of cummulative timing
____________________________________
- number of resets:		{}
- average reset  duration:	{}
- min reset duration:		{}
- max reset duration:		{}
'''.format(cummul_num, cummul_sum / cummul_num, cummul_min, cummul_max))


if __name__ == '__main__':
    main()
