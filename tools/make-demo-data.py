"""
Generate a synthetic demo dataset in the same format as Collect-FSAudit.ps1 output.
Fictional company "Contoso" - all names, SIDs and folders are made up.

Usage:  python tools/make-demo-data.py [output.zip]
"""
import csv, io, json, random, sys, zipfile
from datetime import datetime, timedelta, timezone

random.seed(42)
DOM = 'CONTOSO'
DSID = 'S-1-5-21-1111111111-2222222222-3333333333'
ROOT = r'D:\Shares\Data'
NOW = datetime(2026, 10, 26, 10, 0, tzinfo=timezone.utc)

FULL, MODIFY, RX, READ, WRITE_RX, DELETE = 2032127, 1245631, 1179817, 1179785, 1180095, 65536
RIGHTS = {FULL: 'FullControl', MODIFY: 'Modify, Synchronize', RX: 'ReadAndExecute, Synchronize', READ: 'Read, Synchronize',
          WRITE_RX: 'Write, ReadAndExecute, Synchronize', DELETE: 'Delete'}
EVERYONE, AUTH, SYSTEM, CREATOR = 'S-1-1-0', 'S-1-5-11', 'S-1-5-18', 'S-1-3-0'
BADM, BUSERS = 'S-1-5-32-544', 'S-1-5-32-545'
rid = iter(range(1200, 9999))

# ---------------- principals ----------------
first = ['Anna', 'Mark', 'Laura', 'Peter', 'Julia', 'Tom', 'Kate', 'Oliver', 'Emma', 'Lucas', 'Sofia', 'Daniel', 'Mia', 'Henry', 'Ella',
         'Jack', 'Nora', 'Leo', 'Ava', 'Max', 'Ida', 'Ben', 'Lily', 'Sam', 'Zoe', 'Adam', 'Eva', 'Noah', 'Iris', 'Paul', 'Rose', 'Eric',
         'Lena', 'Hugo', 'Alice', 'Victor', 'Clara', 'Felix', 'Maria', 'Simon']
last = ['Smith', 'Brown', 'Taylor', 'Wilson', 'Clark', 'Hall', 'Young', 'King', 'Wright', 'Scott', 'Green', 'Baker', 'Adams', 'Nelson',
        'Hill', 'Moore', 'Lee', 'White', 'Lewis', 'Walker']
depts = [('Finance', 7), ('Sales', 10), ('Legal', 5), ('HR', 4), ('IT', 5), ('Management', 4), ('Marketing', 5)]
users = []
k = 0
for dept, n in depts:
    for _ in range(n):
        fn, ln = first[k % len(first)], last[(k * 7) % len(last)]
        sam = (fn[0] + ln).lower() + ('' if k < 20 else str(k))
        users.append(dict(Sid=f'{DSID}-{next(rid)}', SamAccountName=sam, DisplayName=f'{fn} {ln}', Department=dept,
                          Title={'IT': 'System Administrator', 'Management': 'Director'}.get(dept, dept + ' Specialist'), Enabled='True'))
        k += 1
admin_users = [dict(Sid=f'{DSID}-500', SamAccountName='Administrator', DisplayName='Administrator', Department='', Title='', Enabled='True'),
               dict(Sid=f'{DSID}-{next(rid)}', SamAccountName='adm.' + users[34]['SamAccountName'], DisplayName='Admin ' + users[34]['DisplayName'].split()[0], Department='IT', Title='Admin account', Enabled='True')]
users += admin_users
for u in random.sample(users[:40], 6): u['Enabled'] = 'False'
svc = dict(Sid=f'{DSID}-{next(rid)}', SamAccountName='svc-backup', DisplayName='svc-backup', Department='', Title='Service account', Enabled='True')
users.append(svc)
for u in users:
    days = random.choice([1, 2, 3, 5, 8, 15, 30]) if u['Enabled'] == 'True' else random.randint(120, 900)
    if random.random() < 0.08 and u['Enabled'] == 'True': days = random.randint(100, 400)
    u['LastLogonDate'] = (NOW - timedelta(days=days, hours=random.randint(0, 9))).isoformat()
    u['UserPrincipalName'] = u['SamAccountName'] + '@contoso.local'
    u['PrimaryGroupSid'] = f'{DSID}-513'
    u['DistinguishedName'] = f"CN={u['DisplayName']},OU=Users,DC=contoso,DC=local"
byDept = {}
for u in users[:40]: byDept.setdefault(u['Department'], []).append(u)

groups = []
def grp(name, scope='Global', sid=None, desc=''):
    g = dict(Sid=sid or f'{DSID}-{next(rid)}', SamAccountName=name, Name=name, GroupScope=scope, GroupCategory='Security', Description=desc,
             DistinguishedName=f'CN={name},OU=Groups,DC=contoso,DC=local')
    groups.append(g); return g
G = {}
G['Domain Users'] = grp('Domain Users', sid=f'{DSID}-513', desc='All domain users')
G['Domain Admins'] = grp('Domain Admins', sid=f'{DSID}-512', desc='Designated administrators of the domain')
G['Administrators'] = grp('Administrators', 'DomainLocal', BADM, 'Built-in administrators')
G['Users'] = grp('Users', 'DomainLocal', BUSERS, 'Built-in users')
for d in byDept: G['GG_' + d] = grp('GG_' + d, desc=d + ' department')
for n in ['DL_Finance_RW', 'DL_Finance_R', 'DL_Payroll_RW', 'DL_Sales_RW', 'DL_Sales_R', 'DL_Contracts_RW', 'DL_Contracts_R', 'DL_Legal_RW',
          'DL_HR_RW', 'DL_IT_Full', 'DL_Management_RW', 'DL_Marketing_RW', 'DL_Archive_R', 'DL_Projects_RW']:
    G[n] = grp(n, 'DomainLocal', desc='File share permission group')
G['GG_Team_Leads'] = grp('GG_Team_Leads', desc='Team leads across departments')
G['DL_Old_Project_X'] = grp('DL_Old_Project_X', 'DomainLocal', desc='Legacy project (no members)')

members = []
def mem(g, m, mtype='user', src='member'):
    members.append(dict(GroupSid=g['Sid'], GroupName=g['SamAccountName'], MemberSid=m['Sid'],
                        MemberName=m.get('SamAccountName', m.get('Name')), MemberType=mtype, MemberDN=m.get('DistinguishedName', ''), Source=src))
for d, us in byDept.items():
    for u in us: mem(G['GG_' + d], u)
for u in users: mem(G['Domain Users'], u, src='primaryGroup')
for g, subs in {'DL_Finance_RW': ['GG_Finance'], 'DL_Finance_R': ['GG_Management'], 'DL_Payroll_RW': [], 'DL_Sales_RW': ['GG_Sales'],
                'DL_Sales_R': ['GG_Management', 'GG_Marketing'], 'DL_Contracts_RW': ['GG_Legal', 'GG_Sales'], 'DL_Contracts_R': ['GG_Finance', 'GG_Management'],
                'DL_Legal_RW': ['GG_Legal'], 'DL_HR_RW': ['GG_HR'], 'DL_IT_Full': ['GG_IT'], 'DL_Management_RW': ['GG_Management'],
                'DL_Marketing_RW': ['GG_Marketing'], 'DL_Archive_R': ['GG_Finance', 'GG_Legal'], 'DL_Projects_RW': ['GG_Team_Leads', 'GG_IT']}.items():
    for sg in subs: mem(G[g], G[sg], 'group')
mem(G['DL_Payroll_RW'], byDept['Finance'][0]); mem(G['DL_Payroll_RW'], byDept['HR'][0])
for d in ['Sales', 'Finance', 'Marketing']: mem(G['GG_Team_Leads'], byDept[d][0])
mem(G['Domain Admins'], users[-2]); mem(G['Domain Admins'], users[-3])
mem(G['Administrators'], G['Domain Admins'], 'group'); mem(G['Administrators'], users[-3])
members.append(dict(GroupSid=BUSERS, GroupName='Users', MemberSid=AUTH, MemberName='NT AUTHORITY\\Authenticated Users', MemberType='foreignSecurityPrincipal', MemberDN='', Source='member'))
mem(G['Users'], G['Domain Users'], 'group')

ORPH1, ORPH2 = f'{DSID}-1105', f'{DSID}-1107'   # deleted accounts
U = {u['SamAccountName']: u for u in users}
someone = lambda d, i=0: byDept[d][i]['Sid']

# ---------------- ACL model ----------------
def ace(sid, allow, mask, ci=True, oi=True, io=False, np=False):
    return dict(sid=sid, allow=allow, mask=mask, ci=ci, oi=oi, io=io, np=np)
def inherit(parent_aces):
    out = []
    for a in parent_aces:
        if not a['ci']: continue
        if a['sid'] == CREATOR:   # creator owner -> owner sid applied at child creation (handled by caller)
            out.append(dict(a, io=True, inh=True)); continue
        if a['np']: out.append(dict(a, ci=False, oi=False, io=False, np=False, inh=True))
        else: out.append(dict(a, io=False, inh=True))
    return out

folders = []   # dicts with id,parent,name,depth,explicit,protected,owner,files,err
def add(parent, name, explicit=None, protected=False, owner=BADM, files=None, err=False):
    f = dict(id=len(folders) + 1, parent=parent['id'] if parent else 0, name=name, depth=(parent['depth'] + 1) if parent else 0,
             explicit=explicit or [], protected=protected, owner=owner, files=random.randint(0, 25) if files is None else files, err=err, kids=[])
    folders.append(f)
    if parent: parent['kids'].append(f)
    return f

drive_inh = [ace(BADM, True, FULL), ace(SYSTEM, True, FULL), ace(AUTH, True, MODIFY), ace(BUSERS, True, RX)]
root = add(None, ROOT, explicit=[ace(ORPH1, False, FULL), ace(CREATOR, True, FULL, io=True), ace(SYSTEM, True, FULL), ace(BADM, True, FULL),
                                 ace(G['Domain Users']['Sid'], True, RX), ace(G['Domain Admins']['Sid'], True, FULL)], files=4)
root['drive_inh'] = drive_inh

base = [ace(SYSTEM, True, FULL), ace(BADM, True, FULL), ace(G['Domain Admins']['Sid'], True, FULL), ace(CREATOR, True, FULL, io=True)]
protect_del = ace(G['Domain Users']['Sid'], False, DELETE, ci=False, oi=False)
def top(name, extra, owner=BADM):
    return add(root, name, explicit=[protect_del] + base + extra + [ace(ORPH2, False, FULL)] * (1 if name in ('Finance', 'Legal') else 0), protected=True, owner=owner)

years = list(range(2019, 2027)); months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
fin = top('Finance', [ace(G['DL_Finance_RW']['Sid'], True, MODIFY), ace(G['DL_Finance_R']['Sid'], True, RX)])
acc = add(fin, 'Accounting')
for y in years:
    yf = add(acc, str(y))
    for m in months[: (10 if y == 2026 else 12)]: add(yf, f'{y}-{m}', files=random.randint(5, 140))
add(fin, 'Budget'); add(fin, 'Reports')
pay = add(fin, 'Payroll', explicit=base + [ace(G['DL_Payroll_RW']['Sid'], True, MODIFY)], protected=True)
for y in years[-4:]: add(pay, str(y), files=random.randint(12, 40))
inv = add(fin, 'Investors', explicit=[ace(byDept['Finance'][1]['Sid'], True, FULL)])   # direct user ACE w/ full control
add(inv, 'Agreements'); add(inv, 'Reporting')

sales = top('Sales', [ace(G['DL_Sales_RW']['Sid'], True, MODIFY), ace(G['DL_Sales_R']['Sid'], True, RX)])
clients = add(sales, 'Clients')
for i in range(1, 321):
    c = add(clients, f'{i:04d} Client {random.choice(last)} {random.choice(["Ltd", "LLC", "Group", "Holding"])}',
            explicit=[ace(G['DL_Sales_RW']['Sid'], True, MODIFY)], owner=random.choice(byDept['Sales'])['Sid'], files=random.randint(0, 6))
    for sub in ['Contracts', 'Offers', 'Scans'] + (['Collateral', 'Valuation'] if i % 3 == 0 else []):
        add(c, sub, owner=c['owner'], files=random.randint(0, 30))
add(sales, 'Pricing'); add(sales, 'Templates')
leads = add(sales, 'Leads 2026', explicit=[ace(byDept['Sales'][3]['Sid'], True, MODIFY), ace(byDept['Sales'][4]['Sid'], True, MODIFY)])

legal = top('Legal', [ace(G['DL_Legal_RW']['Sid'], True, MODIFY)])
contracts = add(legal, 'Contracts', explicit=base + [ace(G['DL_Contracts_RW']['Sid'], True, MODIFY), ace(G['DL_Contracts_R']['Sid'], True, RX)], protected=True)
for y in years:
    yf = add(contracts, str(y))
    for i in range(random.randint(8, 25)): add(yf, f'C-{y}-{i + 1:03d}', files=random.randint(1, 12))
cases = add(legal, 'Cases')
for i in range(1, 41): add(cases, f'Case {2020 + i // 10}-{i:02d}', files=random.randint(1, 50))
add(legal, 'Confidential', explicit=base + [ace(byDept['Legal'][0]['Sid'], True, FULL)], protected=True, err=True)

hr = top('HR', [ace(G['DL_HR_RW']['Sid'], True, MODIFY)])
pers = add(hr, 'Personnel files')
for u in users[:40]: add(pers, u['DisplayName'], files=random.randint(2, 15))
add(hr, 'Recruitment'); add(hr, 'Policies', explicit=[ace(G['Domain Users']['Sid'], True, RX)])

it = top('IT', [ace(G['DL_IT_Full']['Sid'], True, FULL)])
for n in ['Documentation', 'Scripts', 'Licenses', 'Network', 'Backups']: add(it, n)
mgmt = top('Management', [ace(G['DL_Management_RW']['Sid'], True, MODIFY), ace(G['GG_Team_Leads']['Sid'], True, RX)])
board = add(mgmt, 'Board')
for y in years[-4:]: add(board, f'Board meetings {y}', files=random.randint(5, 20))
add(mgmt, 'Strategy')
mkt = top('Marketing', [ace(G['DL_Marketing_RW']['Sid'], True, MODIFY), ace(G['DL_Old_Project_X']['Sid'], True, RX)])
for n in ['Campaigns', 'Brand', 'Photos', 'Events']:
    m = add(mkt, n)
    for y in years[-3:]: add(m, str(y), files=random.randint(3, 120))
pub = top('Public', [ace(EVERYONE, True, MODIFY)])
for n in ['Templates', 'Shared', 'Scanner']: add(pub, n, files=random.randint(5, 60))
proj = top('Projects', [ace(G['DL_Projects_RW']['Sid'], True, MODIFY)])
for n in ['ERP migration', 'Website 2026', 'Office move']: add(proj, n, files=random.randint(3, 30))
arch = top('Archive', [ace(G['DL_Archive_R']['Sid'], True, RX), ace([u for u in users[:40] if u['Enabled'] == 'False'][0]['Sid'], True, MODIFY)])
for y in range(2012, 2019):
    a = add(arch, str(y))
    for d in ['Finance', 'Legal', 'Sales']: add(a, d, files=random.randint(10, 200))

# ---------------- compute ACLs ----------------
acl_ids, acl_rows, frows = {}, [], []
def resolve(f, parent_full):
    if f['parent'] == 0: inh = [dict(a, inh=True) for a in f['drive_inh']]
    elif f['protected']: inh = []
    else:
        inh = inherit(parent_full)
        # creator owner -> owner sid full control on the created folder
        if any(a['sid'] == CREATOR for a in inh) and f['owner'] != BADM and not any(a['sid'] == f['owner'] for a in inh):
            inh.append(dict(sid=f['owner'], allow=True, mask=FULL, ci=True, oi=True, io=False, np=False, inh=True))
    ex = [dict(a, inh=False) for a in f['explicit']]
    order = [a for a in ex if not a['allow']] + [a for a in ex if a['allow']] + [a for a in inh if not a['allow']] + [a for a in inh if a['allow']]
    return order
def key(aces):
    return ';'.join(f"{a['sid']}|{a['allow']}|{a['mask']}|{a['ci']}|{a['oi']}|{a['io']}|{a['np']}|{a['inh']}" for a in aces)
full = {}
for f in folders:
    aces = resolve(f, full.get(f['parent'], []))
    full[f['id']] = aces
    k_ = key(aces)
    if k_ not in acl_ids:
        acl_ids[k_] = len(acl_ids) + 1
        for n, a in enumerate(aces, 1):
            fl = ', '.join(x for x, on in [('ContainerInherit', a['ci']), ('ObjectInherit', a['oi'])] if on) or 'None'
            pf = ', '.join(x for x, on in [('NoPropagateInherit', a['np']), ('InheritOnly', a['io'])] if on) or 'None'
            acl_rows.append(dict(AclId=acl_ids[k_], Order=n, Sid=a['sid'], AccessType='Allow' if a['allow'] else 'Deny', RightsMask=a['mask'],
                                 Rights=RIGHTS.get(a['mask'], str(a['mask'])), InheritanceFlags=fl, PropagationFlags=pf, IsInherited=str(a['inh'])))
    path_parts = []; g = f
    while g: path_parts.insert(0, g['name']); g = folders[g['parent'] - 1] if g['parent'] else None
    lw = (NOW - timedelta(days=random.randint(0, 1500), minutes=random.randint(0, 1440))).isoformat()
    if f['err']:
        frows.append(dict(Id=f['id'], ParentId=f['parent'], Depth=f['depth'], Path='\\'.join(path_parts), Name=f['name'], OwnerSid='', InheritanceDisabled='',
                          AclCanonical='', AclId='', ExplicitAceCount='', InheritedAceCount='', FileCount='', FileBytes='', SubfolderCount='',
                          IsReparsePoint='False', LastWriteUtc=lw, Error='ACL: Attempted to perform an unauthorized operation.'))
        continue
    frows.append(dict(Id=f['id'], ParentId=f['parent'], Depth=f['depth'], Path='\\'.join(path_parts), Name=f['name'] if f['depth'] else ROOT,
                      OwnerSid=f['owner'], InheritanceDisabled=str(f['protected']), AclCanonical='True', AclId=acl_ids[k_],
                      ExplicitAceCount=sum(1 for a in aces if not a['inh']), InheritedAceCount=sum(1 for a in aces if a['inh']),
                      FileCount=f['files'], FileBytes=f['files'] * random.randint(20_000, 900_000), SubfolderCount=len(f['kids']),
                      IsReparsePoint='False', LastWriteUtc=lw, Error=''))

# ---------------- other files ----------------
names = {u['Sid']: f"{DOM}\\{u['SamAccountName']}" for u in users}
names.update({g['Sid']: (('BUILTIN\\' if g['Sid'].startswith('S-1-5-32') else DOM + '\\') + g['SamAccountName']) for g in groups})
names.update({EVERYONE: 'Everyone', AUTH: 'NT AUTHORITY\\Authenticated Users', SYSTEM: 'NT AUTHORITY\\SYSTEM', CREATOR: 'CREATOR OWNER'})
seen = {r['Sid'] for r in acl_rows} | {r['OwnerSid'] for r in frows if r['OwnerSid']}
sids = [dict(Sid=s, Name=names.get(s, ''), Resolved=str(s in names)) for s in sorted(seen)]
shares = [dict(Name='Data', ScopeName='*', Path=ROOT, Description='Company data', Special='False', ShareType='FileSystemDirectory',
               FolderEnumerationMode='Unrestricted', CachingMode='Manual', EncryptData='False', CurrentUsers='12'),
          dict(Name='D$', ScopeName='*', Path='D:\\', Description='Default share', Special='True', ShareType='FileSystemDirectory',
               FolderEnumerationMode='Unrestricted', CachingMode='Manual', EncryptData='False', CurrentUsers='0')]
share_access = [dict(ShareName='Data', ScopeName='*', AccountName='Everyone', Sid=EVERYONE, AccessControlType='Allow', AccessRight='Full')]
errors = [dict(Path=r['Path'], Stage='ACL', Message=r['Error']) for r in frows if r['Error']]
meta = dict(ScriptVersion='1.1', Computer='FS01', RunAs=f'{DOM}\\adm.audit', Elevated=True, IsDomainController=False, PowerShell='5.1',
            RootPath=ROOT, StartUtc=(NOW - timedelta(minutes=2)).isoformat(), EndUtc=NOW.isoformat(),
            Skipped=dict(Folders=False, AD=False, Local=True, Shares=False),
            Counts=dict(Folders=len(frows), UniqueAcls=len(acl_ids), Shares=len(shares), AdUsers=len(users), AdGroups=len(groups),
                        AdMembers=len(members), DomainSid=DSID, Domain='contoso.local', Sids=len(sids), Errors=len(errors)))

def csvtext(rows, header=None):
    b = io.StringIO()
    header = header or (list(rows[0].keys()) if rows else [])
    w = csv.DictWriter(b, fieldnames=header, quoting=csv.QUOTE_ALL, lineterminator='\r\n', extrasaction='ignore')
    w.writeheader(); w.writerows(rows)
    return '\ufeff' + b.getvalue()
UH = ['Sid', 'SamAccountName', 'UserPrincipalName', 'DisplayName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires',
      'AccountExpirationDate', 'WhenCreated', 'Department', 'Title', 'Description', 'Mail', 'Manager', 'PrimaryGroupSid', 'DistinguishedName']
out = sys.argv[1] if len(sys.argv) > 1 else 'demo/demo-audit.zip'
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('folders.csv', csvtext(frows))
    z.writestr('acl_entries.csv', csvtext(acl_rows))
    z.writestr('acl_special.csv', '\ufeff')
    z.writestr('sids.csv', csvtext(sids))
    z.writestr('ad_users.csv', csvtext(users, UH))
    z.writestr('ad_groups.csv', csvtext(groups))
    z.writestr('ad_computers.csv', '\ufeff')
    z.writestr('ad_members.csv', csvtext(members))
    z.writestr('shares.csv', csvtext(shares))
    z.writestr('share_access.csv', csvtext(share_access))
    z.writestr('errors.csv', csvtext(errors, ['Path', 'Stage', 'Message']))
    z.writestr('meta.json', json.dumps(meta, indent=2))
print(f'{out}: {len(frows)} folders, {len(acl_ids)} unique ACLs, {len(users)} users, {len(groups)} groups')
