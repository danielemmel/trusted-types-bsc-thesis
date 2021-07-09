import matplotlib.pyplot as plt


def main():
    vals1, vals2 = [], []
    total_broken, html_broken, script_broken, url_broken, party_broken = [], [], [], [], []
    with open('functionality_results.txt') as f:
        for line in f:
            if 'Total of non-changed inputs:' in line:
                val = line.split('Total of non-changed inputs:')[1].strip()
                working, total = val.split('/')[0], val.split('/')[1]
                val = round(eval(val), 4)
                if len(vals1) < 10:
                    vals1.append(val)
                else:
                    vals2.append(val)
                total_broken.append(int(total) - int(working))
            if 'Total of newly encountered TrustedScriptURL uses:' in line:
                url_broken.append(int(line.split('Total of newly encountered TrustedScriptURL uses:')[1].strip()))
            if 'Total of newly encountered TrustedScript uses:' in line:
                script_broken.append(int(line.split('Total of newly encountered TrustedScript uses:')[1].strip()))
            if 'Total of newly encountered TrustedHTML uses:' in line:
                html_broken.append(int(line.split('Total of newly encountered TrustedHTML uses:')[1].strip()))
            if 'Total of new parties or new TrustedTypes used by existing parties:' in line:
                party_broken.append(int(
                    line.split('Total of new parties or new TrustedTypes used by existing parties:')[1].strip()))
    total_broken = total_broken[:10]
    html_broken = [0.00] + [round(x / y, 4) for x, y in zip(html_broken, total_broken) if x != 0 and y != 0]
    url_broken = [0.00] + [round(x / y, 4) for x, y in zip(url_broken, total_broken) if x != 0 and y != 0]
    script_broken = [0.00] + [round(x / y, 4) for x, y in zip(script_broken, total_broken) if x != 0 and y != 0]
    party_broken = [0.00] + [round(x / y, 4) for x, y in zip(party_broken, total_broken) if x != 0 and y != 0]

    x = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    val3 = ['6103/6103', '5876/5876', '5738/5848', '5562/5771', '5481/5708', '5424/5668', '5205/5492', '5229/5536', '5223/5510', '5166/5468']
    val3 = [round(eval(val), 4) for val in val3]

    plt.figure(1)
    # plotting points as a scatter plot
    plt.scatter(x, vals1, label="without allow-any", color="green",
                marker=".", s=30)
    plt.scatter(x, vals2, label="allow-any with t=10", color="red",
                marker=".", s=30)
    plt.scatter(x, val3, label="from first two data sets, without allow-any", color="blue",
                marker=".", s=30)

    plt.xlabel('Number of day')
    plt.ylabel('Ratio of unchanged inputs')
    plt.legend()

    plt.savefig('functionality.png')

    plt.figure(2)
    x = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    plt.scatter(x, html_broken, label="T-HTML", color="green",
                marker=".", s=30)
    plt.scatter(x, script_broken, label="T-Script", color="red",
                marker=".", s=30)
    plt.scatter(x, url_broken, label="T-ScriptURL", color="blue",
                marker=".", s=30)
    plt.scatter(x, party_broken, label="Parties", color="purple",
                marker=".", s=30)

    plt.xlabel('Number of day')
    plt.ylabel('Ratio of altered inputs')
    plt.legend(loc='upper left')

    # plt.show()
    plt.savefig('broken_inputs.png')

    plt.figure(3)
    activities = ['HTTP', 'blob:', 'local', 'misc', 'protocol-rel']

    slices = [829, 8, 55, 4, 206]

    colors = ['r', 'y', 'g', 'b', 'c']

    plt.pie(slices, labels=activities, colors=colors,
            startangle=90, shadow=True, explode=(0, 0, 0, 0, 0),
            radius=1.2, autopct='%1.1f%%')

    plt.legend()
    plt.savefig('urls.png')


if __name__ == '__main__':
    main()
